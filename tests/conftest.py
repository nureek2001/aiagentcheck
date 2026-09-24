import subprocess

import pytest


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "app.py").write_text(
        "def protected(user):\n    return user.role == 'administrator'\n", encoding="utf-8"
    )
    (root / "README.md").write_text("# Synthetic test fixture\n", encoding="utf-8")
    for args in (
        ["init"],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-m", "fixture"],
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    return root
