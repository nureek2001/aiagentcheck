from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from kmg_agent.config import Settings
from kmg_agent.engine import Engine
from kmg_agent.errors import AnalysisError
from kmg_agent.project import inspect_project
from kmg_agent.proposals import build_patch, propose
from kmg_agent.redaction import Redactor
from kmg_agent.reporting import finalize
from test_engine import FakeDeepSeek


def test_exact_patch_is_generated_without_executing_source():
    source = "raise RuntimeError('must not run')\nx = 1\n"
    patch = build_patch({"app.py": source}, [{"path": "app.py", "before": "x = 1", "after": "x = 2"}])
    assert "-x = 1" in patch and "+x = 2" in patch


@pytest.mark.parametrize(
    "path,before,after",
    [
        ("../app.py", "x = 1", "x = 2"),
        ("app.py", "missing", "x = 2"),
        ("app.py", "x = 1", "def invalid(:"),
        ("app.py", "x = 1", "x = '[REDACTED]'"),
        (".github/a.py", "x = 1", "x = 2"),
    ],
)
def test_unsafe_or_invalid_edits_rejected(path, before, after):
    with pytest.raises(AnalysisError):
        build_patch(
            {"app.py": "x = 1\n", ".github/a.py": "x = 1\n"},
            [{"path": path, "before": before, "after": after}],
        )


def test_overlapping_and_ambiguous_edits_rejected():
    with pytest.raises(AnalysisError):
        build_patch({"a.py": "x = 1\nx = 1\n"}, [{"path": "a.py", "before": "x = 1", "after": "x = 2"}])
    with pytest.raises(AnalysisError):
        build_patch(
            {"a.py": "x = 123\n"},
            [{"path": "a.py", "before": "123", "after": "2"}, {"path": "a.py", "before": "23", "after": "3"}],
        )


def test_proposal_checks_snapshot_and_preserves_target(repo, tmp_path):
    redactor = Redactor()
    project = inspect_project(repo, redactor)
    report = Engine(project, FakeDeepSeek("ИБ-01"), progress=lambda _: None).run()
    output = tmp_path / "assessment"
    output.mkdir()
    final = finalize(report, output, redactor, datetime.now(timezone.utc))
    response = {
        "summary": "Synthetic proposal",
        "risks": [],
        "tests_to_run": ["Check access"],
        "edits": [
            {
                "path": "app.py",
                "before": "return user.role == 'administrator'",
                "after": "return user.is_active and user.role == 'administrator'",
                "reason": "fixture",
            }
        ],
    }
    client = SimpleNamespace(ask=lambda *args: response, usage={"requests": 1})
    result = propose(
        repo,
        output / "report.json",
        final["findings"][0]["id"],
        tmp_path / "patch",
        Settings(key="fixture"),
        redactor,
        client=client,
    )
    assert result["applied"] is False
    assert inspect_project(repo, redactor).fingerprint == project.fingerprint
    final["commit"] = "0" * 40
    from kmg_agent.reporting import write_json

    write_json(output / "report.json", final, redactor)
    with pytest.raises(AnalysisError, match="snapshot"):
        propose(
            repo,
            output / "report.json",
            final["findings"][0]["id"],
            tmp_path / "bad",
            Settings(key="fixture"),
            redactor,
            client=client,
        )
