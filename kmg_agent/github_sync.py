"""Read-only Actions monitoring. Tokens remain on the local server."""

import io
import json
import re
import os
import subprocess
import threading
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jsonschema

from .engine import resource
from .reporting import write_json

ARTIFACT_FILES = {
    "report.json",
    "report.md",
    "metrics.json",
    "inventory.json",
    "execution.log",
    "error.json",
    "progress.json",
    "budget.json",
}
MAX_ARCHIVE = 32 * 1024 * 1024


def github_token():
    """Use an explicit token or the existing Git credential helper without interactive prompts."""
    if os.environ.get("GH_TOKEN"):
        return os.environ["GH_TOKEN"]
    system_git = Path(r"C:\Program Files\Git\cmd\git.exe")
    executable = str(system_git) if os.name == "nt" and system_git.is_file() else "git"
    try:
        result = subprocess.run(
            [executable, "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            text=True,
            capture_output=True,
            timeout=15,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"},
        )
        credentials = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        return credentials.get("password", "") if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def unpack_artifact(data, output, redactor):
    """No extractall: only bounded known basenames; no HTML or executable artifact is trusted."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > 40 or sum(i.file_size for i in infos) > MAX_ARCHIVE:
            raise ValueError("Artifact size limit")
        accepted = {}
        for item in infos:
            if item.filename in ARTIFACT_FILES:
                if item.filename in accepted:
                    raise ValueError("Duplicate artifact member")
                accepted[item.filename] = archive.read(item).decode("utf-8")
        if "report.json" in accepted:
            jsonschema.validate(
                json.loads(accepted["report.json"]), json.loads(resource("report.schema.json"))
            )
        if not accepted:
            raise ValueError("Assessment artifact contains no supported files")
        output.mkdir(parents=True, exist_ok=True)
        for name, value in accepted.items():
            temp = output / (name + ".tmp")
            temp.write_text(redactor.clean(value), encoding="utf-8")
            temp.replace(output / name)


class GitHubSync:
    def __init__(self, repository, token, reports, redactor, interval=20, transport=None):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("GitHub repository must be owner/name")
        if not token:
            raise ValueError("Set GH_TOKEN with Actions:read and repository metadata access")
        self.repository, self.token, self.reports = repository, token, reports
        self.redactor, self.interval = redactor, interval
        self.redactor.known.add(token)
        self.stop = threading.Event()
        self.http = httpx.Client(timeout=20, follow_redirects=False, trust_env=False, transport=transport)

    def api(self, suffix):
        response = self.http.get(
            f"https://api.github.com/repos/{self.repository}/{suffix}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status_code >= 400:
            raise ValueError(f"GitHub HTTP {response.status_code}")
        return response

    def download(self, artifact_id):
        response = self.api(f"actions/artifacts/{int(artifact_id)}/zip")
        if response.status_code != 302:
            raise ValueError("Unexpected GitHub artifact redirect")
        location = response.headers.get("location", "")
        url = urlparse(location)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or not url.hostname.endswith((".blob.core.windows.net", ".githubusercontent.com"))
        ):
            raise ValueError("Unsupported artifact download host")
        # Signed download receives NO GitHub Authorization header.
        with self.http.stream("GET", location) as stream:
            stream.raise_for_status()
            data = bytearray()
            for part in stream.iter_bytes():
                data.extend(part)
                if len(data) > MAX_ARCHIVE:
                    raise ValueError("Artifact download exceeds limit")
        return bytes(data)

    def poll(self):
        runs = self.api("actions/runs?per_page=8").json()["workflow_runs"]
        snapshots = []
        for run in runs:
            item = {
                k: run.get(k)
                for k in (
                    "id",
                    "name",
                    "status",
                    "conclusion",
                    "head_sha",
                    "head_branch",
                    "html_url",
                    "created_at",
                    "run_started_at",
                    "run_attempt",
                )
            }
            item["steps"] = []
            if run["status"] != "completed":
                jobs = self.api(f"actions/runs/{run['id']}/jobs?per_page=30").json()["jobs"]
                item["steps"] = [
                    {
                        "job": j["name"],
                        "name": s["name"],
                        "status": s["status"],
                        "conclusion": s.get("conclusion"),
                    }
                    for j in jobs
                    for s in j.get("steps", [])
                ]
                checks = self.api(f"commits/{run['head_sha']}/check-runs?check_name=KMG%20agent%20progress&per_page=100").json().get("check_runs", [])
                for check in checks:
                    if check.get("external_id") != str(run['id']) + ':' + str(run.get('run_attempt', 1)):
                        continue
                    summary = check.get('output', {}).get('summary', '')
                    if summary.startswith('KMG_PROGRESS_V1\n') and len(summary) < 4096:
                        try:
                            telemetry = json.loads(summary.split('\n', 1)[1])
                            if isinstance(telemetry, dict):
                                item['telemetry'] = telemetry
                        except ValueError:
                            pass
            else:
                directory = self.reports / f"github-{run['id']}-{run.get('run_attempt', 1)}"
                marker = directory / ".synced.json"
                if not marker.exists():
                    artifacts = self.api(f"actions/runs/{run['id']}/artifacts?per_page=100").json()[
                        "artifacts"
                    ]
                    matches = [
                        a
                        for a in artifacts
                        if a["name"].startswith("security-assessment-") and not a.get("expired")
                    ]
                    if matches:
                        unpack_artifact(self.download(matches[0]["id"]), directory, self.redactor)
                        write_json(directory / "github.json", item, self.redactor)
                    write_json(marker, {"artifact_found": bool(matches)}, self.redactor)
            snapshots.append(item)
        write_json(
            self.reports / "github-state.json",
            {"repository": self.repository, "runs": snapshots, "error": None},
            self.redactor,
        )

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    self.poll()
                except (
                    httpx.HTTPError,
                    ValueError,
                    KeyError,
                    OSError,
                    zipfile.BadZipFile,
                    jsonschema.ValidationError,
                ):
                    write_json(
                        self.reports / "github-state.json",
                        {
                            "repository": self.repository,
                            "runs": [],
                            "error": "Не удалось прочитать GitHub Actions. Проверьте GH_TOKEN, доступ и сеть.",
                        },
                        self.redactor,
                    )
                self.stop.wait(self.interval)
        finally:
            self.http.close()
