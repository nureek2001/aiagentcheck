import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from kmg_agent.contracts import MAP, REVIEW, VERIFY
from kmg_agent.engine import Engine, decision
from kmg_agent.project import inspect_project
from kmg_agent.redaction import Redactor
from kmg_agent.reporting import finalize

REF = {"path": "app.py", "start": 1, "end": 2}


class FakeDeepSeek:
    """Transport-free contract fixture, NOT a security model or live assessment."""

    settings = SimpleNamespace(model="MOCK-NOT-DEEPSEEK", context_chars=240000)
    deadline = time.monotonic() + 3600

    def __init__(self, failed=None, verification="confirmed"):
        self.failed, self.verification = failed, verification
        self.usage = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def ask(self, system, payload, schema):
        self.usage["requests"] += 1
        if schema == MAP:
            return {"observations": []}
        if schema == VERIFY:
            return {"verdict": self.verification, "reason": "Synthetic verifier result"}
        assert schema == REVIEW
        fail = payload["requirement"]["id"] == self.failed
        findings = (
            [
                {
                    "title": "Synthetic finding",
                    "severity": "high",
                    "reason": "Synthetic evidence",
                    "recommendation": "Synthetic remediation",
                    "root_cause": "fixture-root",
                    "evidence": [REF],
                }
            ]
            if fail
            else []
        )
        return {
            "status": "fail" if fail else "pass",
            "reason": "Synthetic test assessment",
            "evidence": [REF],
            "findings": findings,
            "requests": [],
        }


@pytest.mark.parametrize("failed,expected", [(None, 0), ("ИБ-01", 1), ("EXTRA", 0)])
def test_full_pipeline_gating_and_artifacts(repo, tmp_path, failed, expected):
    redactor = Redactor()
    project = inspect_project(repo, redactor)
    report = Engine(project, FakeDeepSeek(failed), progress=lambda _: None).run()
    assert decision(report) == expected
    output = tmp_path / "report"
    output.mkdir()
    final = finalize(report, output, redactor, datetime.now(timezone.utc))
    assert final["exit_code"] == expected
    assert len(final["requirements"]) == 8
    assert json.loads((output / "report.json").read_text(encoding="utf-8"))["exit_code"] == expected
    assert "MOCK-NOT-DEEPSEEK" in (output / "report.md").read_text(encoding="utf-8")


def test_rejected_finding_is_not_automatically_a_pass(repo):
    report = Engine(
        inspect_project(repo, Redactor()), FakeDeepSeek("ИБ-01", "rejected"), progress=lambda _: None
    ).run()
    assert decision(report) == 2
    assert not report["findings"]


def test_partial_coverage_cannot_pass(repo):
    report = Engine(inspect_project(repo, Redactor()), FakeDeepSeek(), progress=lambda _: None).run()
    report["coverage"]["chunks_analysed"] = 0
    assert decision(report) == 2
