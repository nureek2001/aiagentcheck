import subprocess
import zipfile

import pytest

from kmg_agent.errors import AnalysisError
from kmg_agent.project import Document, chunk_documents, docx_text, inspect_project
from kmg_agent.redaction import Redactor


def test_inventory_is_read_only(repo):
    before = {p.name: p.read_bytes() for p in repo.iterdir() if p.is_file()}
    git_index = (repo / ".git" / "index").read_bytes()
    project = inspect_project(repo, Redactor())
    assert len(project.commit) == 40
    assert project.evidence({"path": "app.py", "start": 1, "end": 2})["snippet"].startswith("def protected")
    assert before == {p.name: p.read_bytes() for p in repo.iterdir() if p.is_file()}
    assert (repo / ".git" / "index").read_bytes() == git_index


def test_dirty_checkout_rejected(repo):
    (repo / "untracked.py").write_text("x=1")
    with pytest.raises(AnalysisError, match="dirty"):
        inspect_project(repo, Redactor())


@pytest.mark.parametrize(
    "ref",
    [
        {"path": "../outside", "start": 1, "end": 1},
        {"path": "app.py", "start": 0, "end": 1},
        {"path": "app.py", "start": 1, "end": 100},
    ],
)
def test_hallucinated_evidence_rejected(repo, ref):
    with pytest.raises(AnalysisError):
        inspect_project(repo, Redactor()).evidence(ref)


def test_long_lines_are_not_dropped():
    text = "x" * 1600 + "\n" + "last"
    chunks = chunk_documents({"a.js": Document("a.js", text)}, 600)
    result = "".join(s["text"] for c in chunks for s in c["segments"])
    assert result.count("x") == 1600
    assert "last" in result


def test_docx_paragraphs_include_tables(tmp_path):
    path = tmp_path / "spec.docx"
    xml = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>First</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>'
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", xml)
    assert docx_text(path) == "First\nCell"


def test_unknown_binary_fails_closed(repo):
    (repo / "opaque.bin").write_bytes(b"\x00\x01")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.test",
            "commit",
            "-m",
            "binary",
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(AnalysisError, match="binary"):
        inspect_project(repo, Redactor())
