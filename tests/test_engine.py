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


class RecoveryDeepSeek(FakeDeepSeek):
    def __init__(self, mode):
        super().__init__("ИБ-01", "uncertain")
        self.mode = mode
        self.first_reviews = 0
        self.feedback_received = False

    def ask(self, system, payload, schema):
        result = super().ask(system, payload, schema)
        if schema != REVIEW or payload["requirement"]["id"] != "ИБ-01":
            return result
        self.first_reviews += 1
        if self.mode == "invalid" and self.first_reviews == 1 or self.mode == "always_invalid":
            return {**result, "evidence": [{**REF, "end": 999}]}
        if self.mode == "invalid":
            assert "correction" in payload
            return {**result, "status": "pass", "findings": []}
        if self.mode == "feedback" and payload.get("reassessment"):
            self.feedback_received = True
            assert payload["reassessment"]["verifier_feedback"]
            if not payload.get("previous_assessment"):
                return {**result, "status": "needs_context", "findings": [],
                        "requests": [REF]}
            assert payload["source"][0]["snippet"].startswith("def protected")
            return {**result, "status": "pass", "findings": [], "requests": []}
        return result


def test_review_repairs_invalid_ranges_without_clamping(repo):
    client = RecoveryDeepSeek("invalid")
    report = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None).run()
    assert decision(report) == 0
    assert client.first_reviews == 2
    assert report["requirements"][0]["evidence"][0]["end_line"] == 2


def test_rejected_candidate_gets_new_context_in_same_run(repo):
    client = RecoveryDeepSeek("feedback")
    report = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None).run()
    assert client.feedback_received
    assert report["rejected_candidates"]
    assert report["requirements"][0]["status"] == "pass"
    assert decision(report) == 0


def test_unrecoverable_requirement_does_not_skip_other_requirements(repo):
    client = RecoveryDeepSeek("always_invalid")
    report = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None).run()
    assert client.first_reviews == 3
    assert report["requirements"][0]["status"] == "inconclusive"
    assert all(r["status"] == "pass" for r in report["requirements"][1:])
    assert report["coverage"]["extra_checked"]
    assert decision(report) == 2


def test_reassessment_is_bounded_and_never_forces_a_pass(repo):
    client = RecoveryDeepSeek("unresolved")
    report = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None).run()
    assert client.first_reviews == 3
    assert len(report["rejected_candidates"]) == 3
    assert report["requirements"][0]["status"] == "inconclusive"
    assert decision(report) == 2

@pytest.mark.parametrize('mode', ['retrieve', 'invalid', 'exhausted'])
def test_verifier_retrieves_source_or_stays_uncertain(repo, mode):
    class Client(FakeDeepSeek):
        calls = 0

        def ask(self, system, payload, schema):
            assert schema == VERIFY
            self.calls += 1
            if mode == 'retrieve' and self.calls == 2:
                assert payload['retrieved_source'][0]['path'] == 'app.py'
                assert 'administrator' in payload['retrieved_source'][0]['snippet']
                return {'verdict': 'rejected', 'reason': 'Requested source contains enforcement.'}
            ref = {**REF, 'end': 999} if mode == 'invalid' else REF
            return {'verdict': 'needs_context', 'reason': 'Need original enforcement.', 'requests': [ref]}

    client = Client()
    engine = Engine(inspect_project(repo, Redactor()), client, progress=lambda _: None)
    result = engine.request_verification({'requirement': {'id': 'ИБ-01'}, 'retrieved_source': []})
    assert result['verdict'] == ('rejected' if mode == 'retrieve' else 'uncertain')
    assert client.calls == (2 if mode == 'retrieve' else 3)


def test_verification_context_preserves_primary_evidence_and_discloses_omissions(repo):
    client = FakeDeepSeek()
    client.settings = SimpleNamespace(**{**vars(client.settings), "context_chars": 25000})
    engine = Engine(inspect_project(repo, Redactor()), client)
    primary = engine.project.context([REF])
    payload = {"finding": {"title": "candidate"}, "finding_source": primary,
               "file_ranges": [REF], "topology": {}, "requirement": {"id": "ИБ-01"},
               "shared_components": [{"snippet": "x" * 10000}],
               "retrieved_source": [{"snippet": "y" * 10000}], "related_observations": []}
    selected = engine.verification_context(payload)
    assert selected["finding_source"] == primary
    assert selected["file_ranges"] == [REF]
    assert selected["context_selection"]["omitted_items"] == 1
    assert len(json.dumps(selected, ensure_ascii=False)) < 13000


def test_verification_context_never_truncates_oversized_finding(repo):
    from kmg_agent.errors import AnalysisError
    client = FakeDeepSeek()
    client.settings = SimpleNamespace(**{**vars(client.settings), "context_chars": 13000})
    engine = Engine(inspect_project(repo, Redactor()), client)
    with pytest.raises(AnalysisError, match="Finding evidence itself"):
        engine.verification_context({"finding_source": [{"snippet": "x" * 2000}],
                                     "shared_components": [], "retrieved_source": [],
                                     "related_observations": []})
