import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from kmg_agent import cli, worker
from kmg_agent.contracts import MAP, REVIEW
from kmg_agent.engine import Engine, base_report
from kmg_agent.errors import AnalysisError, ProviderError, OutputLimitError
from kmg_agent.project import inspect_project
from kmg_agent.redaction import Redactor
from kmg_agent.reporting import write_json
from test_engine import FakeDeepSeek, REF


def test_hard_timeout_preserves_partial_report(repo, tmp_path, monkeypatch):
    output = tmp_path / "timeout"
    output.mkdir()
    project = inspect_project(repo, Redactor())
    partial = base_report(project, "MOCK-NOT-DEEPSEEK")
    write_json(output / "checkpoint.json", partial, Redactor())
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-key-for-test")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")

    class HungProcess:
        killed = False

        def __init__(self, *args, **kwargs):
            pass

        def wait(self, timeout):
            if self.killed:
                return -1
            raise subprocess.TimeoutExpired("synthetic worker", timeout)

        def kill(self):
            self.killed = True

    monkeypatch.setattr(cli.subprocess, "Popen", HungProcess)
    args = SimpleNamespace(timeout=10, env_file=tmp_path / "absent", workers=1)
    assert cli.run_scan(args, repo, output, Redactor()) == 2
    final = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert final["result"] == "incomplete"
    assert final["coverage"]["chunks_analysed"] == 0
    assert "CHECK NOT COMPLETED" in (output / "execution.log").read_text()


def test_provider_failure_does_not_leave_assessment(repo, tmp_path, monkeypatch):
    output = tmp_path / "provider-failure"
    output.mkdir()
    for name in ("checkpoint.json", "report.json", "report.md"):
        (output / name).write_text("previous partial")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-key-for-test")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker",
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--deadline",
            str(time.monotonic() + 30),
            "--started",
            datetime.now(timezone.utc).isoformat(),
        ],
    )

    def unavailable(self):
        raise ProviderError("DeepSeek unavailable")

    monkeypatch.setattr(worker.Engine, "run", unavailable)
    assert worker.main() == 2
    assert (output / "error.json").exists()
    assert not (output / "report.json").exists()
    assert not (output / "report.md").exists()
    assert not (output / "checkpoint.json").exists()


def test_retrieval_round_supplies_actual_source(repo):
    class RetrievalClient(FakeDeepSeek):
        requested = False

        def ask(self, system, payload, schema):
            if schema == REVIEW and payload["requirement"]["id"] == "ИБ-01":
                if not self.requested:
                    self.requested = True
                    return {
                        "status": "needs_context",
                        "reason": "Need wrapper body",
                        "evidence": [],
                        "findings": [],
                        "requests": [REF],
                    }
                assert payload["source"][0]["snippet"].startswith("def protected")
            return super().ask(system, payload, schema)

    client = RetrievalClient()
    report = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None).run()
    assert report["exit_code"] == 0
    assert client.requested


def test_map_cannot_cite_another_chunk(repo):
    class BadMap(FakeDeepSeek):
        def ask(self, system, payload, schema):
            if schema == MAP:
                return {
                    "observations": [{"requirement": "ИБ-01", "fact": "Unseen evidence", "evidence": [REF]}]
                }
            return super().ask(system, payload, schema)

    project = inspect_project(repo, Redactor())
    engine = Engine(project, BadMap())
    with pytest.raises(AnalysisError, match="outside"):
        engine.map_chunk({"id": 1, "segments": [{"path": "README.md", "start": 1, "end": 1, "text": "test"}]})


def test_output_limit_subdivides_context_without_omission(repo):
    class LimitedClient(FakeDeepSeek):
        seen = []

        def ask(self, system, payload, schema):
            if schema == MAP:
                segments = payload["chunk"]["segments"]
                if len(segments) > 1:
                    raise OutputLimitError("Synthetic output limit")
                self.seen.append(segments[0]["path"])
                return {"observations": []}
            return super().ask(system, payload, schema)

    project = inspect_project(repo, Redactor())
    client = LimitedClient()
    report = Engine(project, client, progress=lambda _: None).run()
    assert report["exit_code"] == 0
    assert set(client.seen) == set(project.documents)


def test_map_accepts_adjacent_supplied_ranges_but_rejects_gaps(repo):
    project = inspect_project(repo, Redactor())
    engine = Engine(project, FakeDeepSeek())
    observation = {"observations": [{"requirement": "ИБ-01", "fact": "wrapper", "evidence": [REF]}]}
    chunk = {
        "id": 1,
        "segments": [
            {"path": "app.py", "start": 1, "end": 1},
            {"path": "app.py", "start": 2, "end": 2},
        ],
    }
    engine.validate_map(observation, chunk)
    chunk["segments"].pop()
    with pytest.raises(AnalysisError, match="outside"):
        engine.validate_map(observation, chunk)


def test_bad_map_recovery_subdivides_without_silently_skipping_source(repo):
    class RecoveringClient(FakeDeepSeek):
        seen = []

        def ask(self, system, payload, schema):
            if schema == MAP:
                segments = payload["chunk"]["segments"]
                if len(segments) > 1:
                    return {
                        "observations": [
                            {
                                "requirement": "ИБ-01",
                                "fact": "bad",
                                "evidence": [{"path": "missing.py", "start": 1, "end": 2}],
                            }
                        ]
                    }
                self.seen.append(segments[0]["path"])
                return {"observations": []}
            return super().ask(system, payload, schema)

    project = inspect_project(repo, Redactor())
    client = RecoveringClient()
    report = Engine(project, client, progress=lambda _: None).run()
    assert report["exit_code"] == 0
    assert set(client.seen) == set(project.documents)
