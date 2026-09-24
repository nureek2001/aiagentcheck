import pytest

from kmg_agent.cli import main, prepare_output
from kmg_agent.config import Settings, load_env
from kmg_agent.redaction import Redactor


def test_output_cannot_modify_target(repo):
    with pytest.raises(ValueError, match="outside"):
        prepare_output(repo, repo / "reports")


def test_existing_results_not_overwritten(repo, tmp_path):
    output = tmp_path / "previous"
    output.mkdir()
    (output / "report.json").write_text("old")
    with pytest.raises(ValueError, match="empty"):
        prepare_output(repo, output)


def test_missing_key_code_two(repo, tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    output = tmp_path / "missing-key"
    assert (
        main(["scan", "--repo", str(repo), "--output", str(output), "--env-file", str(tmp_path / "absent")])
        == 2
    )
    assert not (output / "report.json").exists()
    assert "exit_code=2" in (output / "execution.log").read_text()


def test_offline_inspect(repo, tmp_path):
    output = tmp_path / "inventory"
    assert main(["inspect", "--repo", str(repo), "--output", str(output)]) == 0
    assert (output / "inventory.json").is_file()
    assert not (output / "report.json").exists()


def test_env_does_not_execute_and_environment_wins(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("DEEPSEEK_API_KEY=file-value\nSAFE_VALUE=$(danger)\n")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "environment-value")
    monkeypatch.delenv("SAFE_VALUE", raising=False)
    load_env(path)
    import os

    assert os.environ["DEEPSEEK_API_KEY"] == "environment-value"
    assert os.environ["SAFE_VALUE"] == "$(danger)"


def test_key_cannot_be_sent_to_another_provider(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "secret")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://example.test")
    with pytest.raises(ValueError, match="official"):
        Settings.from_env()


def test_redaction_preserves_lines_and_removes_repeated_secret():
    redactor = Redactor(["actual-api-key"])
    text = 'password = "sensitive123"\nprint("sensitive123")\nactual-api-key\nTraining-2026!operator'
    result = redactor.clean(text)
    for secret in ("sensitive123", "actual-api-key", "Training-2026!operator"):
        assert secret not in result
    assert result.count("\n") == text.count("\n")


def test_redaction_preserves_executable_token_and_key_expressions():
    source = (
        "token = actor.set(request.user.pk)\nSECRET_KEY = (RUNTIME / 'keys' / 'django.key').read_text()\n"
    )
    assert Redactor().clean(source) == source
