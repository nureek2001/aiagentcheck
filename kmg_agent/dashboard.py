"""Loopback dashboard and portable CI artifact, with explicit opt-in proposals."""

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jsonschema

from .config import Settings, load_env
from .errors import AgentError
from .redaction import Redactor

DOWNLOADS = {
    "report.json",
    "report.md",
    "execution.log",
    "metrics.json",
    "inventory.json",
    "error.json",
    "proposal.json",
    "proposal.patch",
    "dashboard.html",
    "budget.json",
    "pr.json",
}


def read_json(path, default=None):
    try:
        if path.stat().st_size > 32 * 1024 * 1024:
            return default
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, ValueError):
        return default


def assessment(directory):
    report = read_json(directory / "report.json")
    error = read_json(directory / "error.json")
    checkpoint = read_json(directory / "checkpoint.json")
    progress = read_json(directory / "progress.json", {})
    result = report or checkpoint
    if result:
        result = {
            **result,
            "coverage": {k: v for k, v in result.get("coverage", {}).items() if k != "inventory"},
        }
    # Final files take precedence over stale progress if a worker died or timed out.
    if report or error:
        progress = {**progress, "status": "completed", "stage": "error" if error else "finished"}
    elif progress.get("status") == "running":
        try:
            timestamp = datetime.fromisoformat(progress["updated_at"])
            if (datetime.now(timezone.utc) - timestamp).total_seconds() > 300:
                progress = {
                    **progress,
                    "status": "stale",
                    "message": "Нет свежих событий; состояние неизвестно",
                }
        except (KeyError, ValueError):
            pass
    proposal = read_json(directory / "proposal.json")
    full_patch = ""
    if proposal:
        try:
            full_patch = (directory / "proposal.patch").read_text(encoding="utf-8")
            proposal["diff"] = full_patch[:200000]
            proposal["diff_truncated"] = len(full_patch) > 200000
        except OSError:
            proposal["diff"] = ""
    patch_hash = hashlib.sha256(full_patch.encode()).hexdigest() if proposal else None
    return {
        "budget": read_json(directory / "budget.json"),
        "pr": read_json(directory / "pr.json"),
        "patch_sha256": patch_hash,
        "id": directory.name,
        "report": result,
        "final": report is not None,
        "progress": progress,
        "error": error,
        "proposal": proposal,
        "github": read_json(directory / "github.json"),
        "files": sorted(n for n in DOWNLOADS if (directory / n).is_file()),
    }


def asset(name):
    return files("kmg_agent").joinpath("web", name).read_text(encoding="utf-8")


def export_dashboard(output):
    state = {"runs": [assessment(output)], "github": None, "can_propose": False, "live": False}
    embedded = json.dumps(state, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    page = asset("index.html").replace(
        '<link rel="stylesheet" href="/app.css">', "<style>" + asset("app.css") + "</style>"
    )
    page = page.replace(
        '<script src="/app.js" defer></script>',
        '<script id="initial-state" type="application/json">'
        + embedded
        + "</script><script defer>"
        + asset("app.js")
        + "</script>",
    )
    (output / "dashboard.html").write_text(page, encoding="utf-8")


class Dashboard:
    def __init__(self, reports, repo=None, env_file=Path(".env")):
        self.reports = reports.resolve()
        self.reports.mkdir(parents=True, exist_ok=True)
        self.repo = repo.resolve() if repo else None
        self.env_file = env_file.resolve()
        self.csrf = secrets.token_urlsafe(32)
        self.lock, self.process = threading.Lock(), None
        self.scan_destination = None
        self.budget_settings = read_json(self.reports / '.budget-settings.json', {"max_tokens": 8000000, "max_requests": 250})

    def directory(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", name) or name.startswith("."):
            raise ValueError("Invalid run identifier")
        path = (self.reports / name).resolve()
        if path.parent != self.reports or not path.is_dir():
            raise ValueError("Unknown run")
        return path

    def state(self):
        directories = sorted(
            (
                d
                for d in self.reports.iterdir()
                if d.is_dir() and not d.name.startswith(".") and d.resolve().parent == self.reports
            ),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )[:60]
        runs = [assessment(d) for d in directories]
        runs = [r for r in runs if r["report"] or r["error"] or r["progress"] or r["proposal"]]
        if self.scan_destination and self.process is not None and self.process.poll() is None and not any(r['id'] == self.scan_destination for r in runs):
            runs.insert(0, {'id': self.scan_destination, 'report': None, 'final': False, 'error': None,
                           'proposal': None, 'files': [], 'progress': {'stage': 'inventory', 'status': 'running', 'message': 'Preparing scan'}})
        return {
            "runs": runs,
            "github": read_json(self.reports / "github-state.json"),
            "can_propose": bool(self.repo and os.environ.get("DEEPSEEK_API_KEY")),
            "proposal_busy": self.process is not None and self.process.poll() is None,
            "benchmark": read_json(self.reports / "benchmark.json"),
            "budget_settings": self.budget_settings,
            "can_scan": bool(self.repo and os.environ.get("DEEPSEEK_API_KEY")),
            "can_publish": bool(self.repo),
            "csrf": self.csrf,
            "live": True,
        }

    def start_proposal(self, run, finding):
        if not self.repo:
            raise ValueError("No local target configured for proposals")
        source = self.directory(run) / "report.json"
        report = read_json(source, {})
        if finding not in {f["id"] for f in report.get("findings", [])}:
            raise ValueError("Unknown finding")
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise ValueError("A proposal is already being prepared")
            destination = self.reports / ("proposal-" + secrets.token_hex(6))
            destination.mkdir()
            with (destination / "execution.log").open("w", encoding="utf-8") as log:
                self.process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "kmg_agent",
                        "propose",
                        "--repo",
                        str(self.repo),
                        "--report",
                        str(source),
                        "--finding",
                        finding,
                        "--output",
                        str(destination),
                        "--env-file",
                        str(self.env_file),
                    ],
                    stdout=log,
                    stderr=log,
                    env=self.child_env(),
                )
            return destination.name

    def child_env(self):
        return {**os.environ, "PYTHONUTF8": "1",
                "DEEPSEEK_MAX_TOKENS": str(self.budget_settings["max_tokens"]),
                "DEEPSEEK_MAX_REQUESTS": str(self.budget_settings["max_requests"])}

    def set_budget(self, data):
        tokens, requests = data.get('max_tokens'), data.get('max_requests')
        if type(tokens) is not int or type(requests) is not int or not 1000 <= tokens <= 50000000 or not 1 <= requests <= 2000:
            raise ValueError('Invalid budget')
        from .reporting import write_json
        self.budget_settings = {'max_tokens': tokens, 'max_requests': requests}
        write_json(self.reports / '.budget-settings.json', self.budget_settings, Redactor())
        return self.budget_settings

    def start_scan(self):
        if not self.repo:
            raise ValueError('Local target required')
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise ValueError('A task is already running')
            destination = self.reports / ('run-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
            self.scan_destination = destination.name
            with (self.reports / '.scan.log').open('w', encoding='utf-8') as log:
                self.process = subprocess.Popen([sys.executable, '-m', 'kmg_agent', 'scan', '--repo', str(self.repo),
                    '--output', str(destination), '--env-file', str(self.env_file), '--no-cache'],
                    stdout=log, stderr=log, env=self.child_env())
            return destination.name

    def start_publish(self, name, patch_hash):
        if not self.repo:
            raise ValueError('Local target required')
        directory = self.directory(name)
        if hashlib.sha256((directory / 'proposal.patch').read_text(encoding='utf-8').encode()).hexdigest() != patch_hash:
            raise ValueError('Patch changed')
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise ValueError('A task is already running')
            with (directory / 'publication.log').open('w', encoding='utf-8') as log:
                self.process = subprocess.Popen([sys.executable, '-m', 'kmg_agent', 'publish-proposal',
                    '--repo', str(self.repo), '--proposal', str(directory), '--patch-sha256', patch_hash, '--confirm'],
                    stdout=log, stderr=log, env=self.child_env())
            return name


def handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, content, mime="application/json", filename=None):
            if not isinstance(content, bytes):
                content = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; "
                "style-src 'self'; connect-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'; base-uri 'none'",
            )
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(content)

        def allowed_host(self):
            return self.headers.get("Host") in {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }

        def do_GET(self):
            if not self.allowed_host():
                self.respond(403, "{}")
                return
            route = urlparse(self.path)
            if route.path in {"/", "/app.css", "/app.js"}:
                name, mime = {
                    "/": ("index.html", "text/html"),
                    "/app.css": ("app.css", "text/css"),
                    "/app.js": ("app.js", "text/javascript"),
                }[route.path]
                self.respond(200, asset(name), mime)
            elif route.path == "/api/state":
                self.respond(200, json.dumps(app.state(), ensure_ascii=False))
            elif route.path == "/download":
                try:
                    params = parse_qs(route.query)
                    name = params["file"][0]
                    if name not in DOWNLOADS:
                        raise ValueError("Unsupported file")
                    path = app.directory(params["run"][0]) / name
                    if path.is_symlink() or path.resolve().parent != path.parent:
                        raise ValueError("Invalid file")
                    self.respond(200, path.read_bytes(), "application/octet-stream", name)
                except (KeyError, ValueError, OSError):
                    self.respond(404, "{}")
            else:
                self.respond(404, "{}")

        def do_POST(self):
            origin = self.headers.get("Origin")
            if (
                not self.allowed_host()
                or origin
                not in {
                    f"http://127.0.0.1:{self.server.server_port}",
                    f"http://localhost:{self.server.server_port}",
                }
                or not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), app.csrf)
            ):
                self.respond(403, "{}")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path not in {"/api/propose", "/api/scan", "/api/budget", "/api/publish"} or not 0 < length < 4096:
                    raise ValueError("Invalid proposal request")
                data = json.loads(self.rfile.read(length))
                if self.path == '/api/budget':
                    self.respond(200, json.dumps(app.set_budget(data)))
                    return
                if self.path == '/api/publish':
                    if data.get('confirm_push_tests_paid_rescan') is not True:
                        raise ValueError('Explicit publication confirmation required')
                    self.respond(202, json.dumps({'run': app.start_publish(data['run'], data['patch_sha256'])}))
                    return
                if data.get("confirm_paid_request") is not True:
                    raise ValueError("Explicit paid request confirmation required")
                run = app.start_scan() if self.path == "/api/scan" else app.start_proposal(data["run"], data["finding"])
                self.respond(202, json.dumps({"run": run}))
            except (ValueError, KeyError, TypeError, OSError):
                self.respond(
                    400, json.dumps({"error": "Предложение не запущено: проверьте выбор и текущие задачи."})
                )

    return Handler


def command(args):
    try:
        if args.command == "dashboard-export":
            export_dashboard(args.output)
            return 0
        if args.repo and args.env_file.resolve().is_relative_to(args.repo.resolve()):
            raise ValueError("Agent env-file must be outside target")
        load_env(args.env_file)
        if args.command == "propose":
            from .cli import prepare_output
            from .proposals import propose
            from .reporting import write_json

            # The server reserves an empty directory before starting this command.
            output = args.output.resolve()
            if output.exists() and set(p.name for p in output.iterdir()) <= {"execution.log"}:
                repo = args.repo.resolve(strict=True)
                if output.is_relative_to(repo):
                    raise ValueError("Proposal output must be outside target")
            else:
                repo, output = prepare_output(args.repo, output)
            redactor = Redactor([os.environ.get("DEEPSEEK_API_KEY", "")])
            write_json(
                output / "progress.json",
                {
                    "stage": "proposal",
                    "status": "running",
                    "message": "DeepSeek готовит предложение",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                redactor,
            )
            try:
                result = propose(repo, args.report, args.finding, output, Settings.from_env(), redactor)
            except (AgentError, OSError, ValueError, jsonschema.ValidationError) as exc:
                write_json(
                    output / "error.json",
                    {"exit_code": 2, "message": redactor.clean(str(exc))[:800]},
                    redactor,
                )
                raise
            write_json(
                output / "progress.json",
                {
                    "stage": "finished",
                    "status": "completed",
                    "message": "Предложение сохранено; исходники не изменены",
                },
                redactor,
            )
            print(result["status"])
            return 0
        app = Dashboard(args.reports, args.repo, args.env_file)
        server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(app))
        sync = None
        if args.github_repo:
            from .github_sync import GitHubSync, github_token

            sync = GitHubSync(
                args.github_repo,
                github_token(),
                app.reports,
                Redactor([os.environ.get("DEEPSEEK_API_KEY", "")]),
            )
            threading.Thread(target=sync.run, daemon=True).start()
        print(f"Dashboard: http://127.0.0.1:{server.server_port} (no automatic DeepSeek calls)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            if sync:
                sync.stop.set()
        return 0
    except (AgentError, OSError, ValueError, jsonschema.ValidationError):
        print("Command failed; check input, snapshot, credentials and diagnostic files.", file=sys.stderr)
        return 2
