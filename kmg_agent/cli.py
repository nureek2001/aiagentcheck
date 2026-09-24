"""Public noninteractive CLI with isolated execution and fail-closed exit codes."""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings, load_env
from .errors import AgentError
from .project import compact_index, inspect_project
from .redaction import Redactor
from .reporting import finalize, write_json


def parser():
    result = argparse.ArgumentParser(description="KMG Security Agent — DeepSeek requirement audit")
    result.add_argument("--version", action="version", version="1.0.0")
    sub = result.add_subparsers(dest="command", required=True)
    dashboard = sub.add_parser("dashboard", help="Local live dashboard; does not start scans")
    dashboard.add_argument("--reports", type=Path, default=Path("reports"))
    dashboard.add_argument("--repo", type=Path, help="Optional clean target for proposal generation")
    dashboard.add_argument("--github-repo", help="Team repository owner/name; read-only Actions sync")
    dashboard.add_argument("--env-file", type=Path, default=Path(".env"))
    dashboard.add_argument("--port", type=int, default=8765)
    export = sub.add_parser("dashboard-export", help="Standalone dashboard from existing results")
    export.add_argument("--output", type=Path, required=True, help="Existing assessment directory")
    propose = sub.add_parser("propose", help="Suggest a patch without changing or executing target code")
    propose.add_argument("--repo", type=Path, required=True)
    propose.add_argument("--report", type=Path, required=True)
    propose.add_argument("--finding", required=True)
    propose.add_argument("--output", type=Path, required=True)
    propose.add_argument("--env-file", type=Path, default=Path(".env"))
    for name in ("scan", "inspect"):
        command = sub.add_parser(
            name, help="Full DeepSeek assessment" if name == "scan" else "Offline inventory only"
        )
        command.add_argument("--repo", required=True, type=Path, help="Clean target Git repository root")
        command.add_argument("--output", required=True, type=Path, help="New/empty directory OUTSIDE target")
        if name == "scan":
            command.add_argument("--env-file", type=Path, default=Path(".env"))
            command.add_argument("--timeout", type=int, default=1500, help="Total seconds, range 10..1740")
            command.add_argument("--workers", type=int, choices=range(1, 5), default=2)
            command.add_argument(
                "--no-cache", action="store_true", help="Do not reuse prior context observations"
            )
    return result


def prepare_output(repo, output):
    repo, output = repo.resolve(strict=True), output.resolve()
    if output == repo or output.is_relative_to(repo):
        raise ValueError("Output must be outside the checked repository")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Output must be new or empty; stale reports cannot be reused")
    output.mkdir(parents=True, exist_ok=True)
    return repo, output


def run_scan(args, repo, output, redactor):
    if not 10 <= args.timeout <= 1740:
        raise ValueError("Timeout must be 10..1740 seconds, leaving reserve below 30 minutes")
    # Do not read target secrets as agent configuration.
    env_path = args.env_file.resolve()
    if env_path.is_relative_to(repo):
        raise ValueError("Agent env-file must not be inside the target repository")
    load_env(env_path)
    settings = Settings.from_env()
    redactor.known.add(settings.key)
    started = datetime.now(timezone.utc)
    deadline = time.monotonic() + args.timeout
    command = [
        sys.executable,
        "-m",
        "kmg_agent.worker",
        "--repo",
        str(repo),
        "--output",
        str(output),
        "--deadline",
        str(deadline),
        "--started",
        started.isoformat(),
        "--workers",
        str(args.workers),
    ]
    if not getattr(args, "no_cache", False):
        command.extend(["--cache-dir", str(output.parent / ".context-cache")])
    print(f"Starting DeepSeek scan; model={settings.model}; deadline={args.timeout}s", flush=True)
    # Worker logs only stage identifiers and safe diagnostics, never raw source/provider bodies.
    with (output / "execution.log").open("w", encoding="utf-8") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log, env={**os.environ, "PYTHONUTF8": "1"})
        try:
            code = child.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
            code = 2
            checkpoint = output / "checkpoint.json"
            if checkpoint.exists():
                report = json.loads(checkpoint.read_text(encoding="utf-8"))
                report["limitations"].append(
                    "Hard wall-clock deadline reached; remaining checks not completed"
                )
                finalize(report, output, redactor, started, code=2)
            write_json(
                output / "error.json",
                {"exit_code": 2, "kind": "deadline", "message": "Time limit reached"},
                redactor,
            )
            log.write("Hard timeout; exit_code=2\n")
        except KeyboardInterrupt:
            child.kill()
            child.wait(timeout=10)
            write_json(
                output / "error.json",
                {"exit_code": 2, "kind": "interrupted", "message": "Scan interrupted"},
                redactor,
            )
            code = 2
    code = code if code in (0, 1, 2) else 2
    report_path = output / "report.json"
    if code in (0, 1) and not report_path.exists():
        code = 2
    count, ids = 0, []
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["exit_code"] != code:
            report["limitations"].append("Worker exit code and report disagreed; verification incomplete")
            report = finalize(report, output, redactor, started, code=2)
            code = 2
        count = len(report["findings"])
        ids = sorted({x["requirement"] for x in report["findings"]})
    summary = f"exit_code={code}; violations={count}; requirements={','.join(ids) or 'none'}"
    if code == 2:
        summary += "; CHECK NOT COMPLETED"
    with (output / "execution.log").open("a", encoding="utf-8") as log:
        log.write(summary + "\n")
    print(summary, flush=True)
    (output / "checkpoint.json").unlink(missing_ok=True)
    from .dashboard import export_dashboard

    export_dashboard(output)
    return code


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command in {"dashboard", "dashboard-export", "propose"}:
        from .dashboard import command

        return command(args)
    redactor = Redactor([os.environ.get("DEEPSEEK_API_KEY", "")])
    output = None
    try:
        repo, output = prepare_output(args.repo, args.output)
        if args.command == "inspect":
            project = inspect_project(repo, redactor)
            write_json(output / "inventory.json", compact_index(project), redactor)
            print(
                f"Inventory: {len(project.documents)} text files, {len(project.chunks)} chunks. NOT a security assessment."
            )
            return 0
        return run_scan(args, repo, output, redactor)
    except (AgentError, OSError, ValueError) as exc:
        message = str(exc) if isinstance(exc, (AgentError, ValueError)) else "Filesystem operation failed"
        message = redactor.clean(message)
        if output:
            write_json(
                output / "error.json",
                {"exit_code": 2, "kind": "configuration_or_input", "message": message},
                redactor,
            )
            (output / "execution.log").write_text(
                f"exit_code=2; violations=0; requirements=none; CHECK NOT COMPLETED; {message}\n",
                encoding="utf-8",
            )
        print("exit_code=2; " + message, file=sys.stderr)
        return 2
