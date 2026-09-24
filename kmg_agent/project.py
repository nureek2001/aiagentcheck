"""Read-only inventory, document extraction, AST facts and complete text chunking."""

import ast
import hashlib
import json
import os
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from .errors import AnalysisError

BINARY = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mo"}
SECRET = {".pem", ".key", ".p12", ".pfx", ".sqlite3", ".db"}
MAX_FILE = 12 * 1024 * 1024
MAX_TOTAL = 80 * 1024 * 1024


def git(root, *args):
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
            capture_output=True,
            timeout=30,
            check=True,
            env={
                **{
                    k: v
                    for k, v in os.environ.items()
                    if k not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}
                },
                "GIT_OPTIONAL_LOCKS": "0",
            },
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise AnalysisError("Git operation failed; use an accessible, clean Git checkout") from exc


@dataclass
class Document:
    path: str
    text: str
    kind: str = "source"
    facts: list = field(default_factory=list)

    def lines(self):
        return self.text.splitlines() or [""]


@dataclass
class Project:
    root: Path
    commit: str
    documents: dict
    inventory: list
    fingerprint: str
    chunks: list

    def evidence(self, ref):
        path, start, end = ref["path"], ref["start"], ref["end"]
        if path not in self.documents:
            raise AnalysisError("Model referenced an unknown or excluded file")
        doc = self.documents[path]
        lines = doc.lines()
        if not (1 <= start <= end <= len(lines)):
            raise AnalysisError(f"Invalid evidence range {start}-{end}; file has {len(lines)} lines")
        return {
            "path": path,
            "line": start if doc.kind != "docx" else None,
            "end_line": end if doc.kind != "docx" else None,
            "locator": f"paragraphs {start}-{end}" if doc.kind == "docx" else f"lines {start}-{end}",
            "snippet": "\n".join(lines[start - 1 : end]),
        }

    def context(self, refs):
        return [self.evidence(ref) for ref in refs]


def docx_text(path):
    with zipfile.ZipFile(path) as archive:
        entries = [x for x in archive.infolist() if x.filename == "word/document.xml"]
        if len(entries) != 1 or entries[0].file_size > MAX_FILE:
            raise AnalysisError("Unsupported DOCX size or structure")
        xml = ElementTree.fromstring(archive.read(entries[0]))
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    return "\n".join(
        "".join(t.text or "" for t in p.findall(".//w:t", ns)) for p in xml.findall(".//w:body//w:p", ns)
    )


def ast_facts(text, path):
    if not path.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [{"type": "parse_error", "note": "Python AST unavailable; text still analysed"}]
    facts = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            facts.append(
                {
                    "type": type(node).__name__,
                    "name": node.name,
                    "line": node.lineno,
                    "end": node.end_lineno,
                    "decorators": [ast.unparse(d) for d in node.decorator_list],
                }
            )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            facts.append({"type": "import", "line": node.lineno, "value": ast.unparse(node)})
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"path", "re_path"}
        ):
            facts.append({"type": "route", "line": node.lineno, "value": ast.unparse(node)})
    return facts


def chunk_documents(documents, limit):
    """All extracted text is covered. Long individual lines are split, not dropped."""
    chunks, parts, size = [], [], 0

    def flush():
        nonlocal parts, size
        if parts:
            chunks.append({"id": len(chunks) + 1, "segments": parts})
        parts, size = [], 0

    for doc in documents.values():
        for number, line in enumerate(doc.lines(), 1):
            for offset in range(0, max(len(line), 1), limit // 2):
                piece = line[offset : offset + limit // 2]
                overhead = len(str(number)) + 3
                new_segment = not parts or parts[-1]["path"] != doc.path or offset != 0
                if new_segment:
                    overhead += len(doc.path) + 120
                if size + len(piece) + overhead > limit:
                    flush()
                if parts and parts[-1]["path"] == doc.path and offset == 0:
                    parts[-1]["text"] += f"\n{number}: {piece}"
                    parts[-1]["end"] = number
                else:
                    parts.append(
                        {
                            "path": doc.path,
                            "kind": doc.kind,
                            "start": number,
                            "end": number,
                            "text": f"{number}: {piece}",
                        }
                    )
                size += len(piece) + overhead
    flush()
    return chunks


def inspect_project(root: Path, redactor, chunk_chars=90000):
    root = root.resolve(strict=True)
    git_root = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if git_root != root:
        raise AnalysisError("Target must be the Git repository root")
    if git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise AnalysisError("Target checkout is dirty; commit changes or use a clean checkout")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    paths = sorted(p.decode("utf-8") for p in git(root, "ls-files", "-z").split(b"\0") if p)
    inventory, documents, hasher, total = [], {}, hashlib.sha256(), 0
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise AnalysisError("Symlinks and paths outside target are not supported")
        if not path.is_file():
            raise AnalysisError("Missing tracked file or uninitialised submodule")
        length = path.stat().st_size
        total += length
        if length > MAX_FILE or total > MAX_TOTAL:
            raise AnalysisError("Input size limit exceeded; no successful assessment is possible")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        hasher.update(relative.encode() + b"\0" + digest.encode())
        item = {"path": relative, "bytes": length, "sha256": digest}
        suffix = path.suffix.lower()
        if suffix in BINARY:
            item.update(status="excluded", reason="binary visual/font/localisation asset; no source text")
        elif (
            suffix in SECRET
            or path.name == ".env"
            or path.name.startswith(".env.")
            and path.name != ".env.example"
        ):
            # Presence remains visible for repository hygiene assessment, contents never sent.
            item.update(
                status="excluded", reason="potential secret/runtime material; contents not transmitted"
            )
        else:
            try:
                text = docx_text(path) if suffix == ".docx" else raw.decode("utf-8-sig")
            except (UnicodeError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
                raise AnalysisError(
                    "Unsupported tracked document/binary; inventory cannot be completed"
                ) from exc
            if "\x00" in text:
                raise AnalysisError("Unrecognised binary file; cannot silently omit it")
            redactor.discover(text)
            documents[relative] = Document(relative, text, "docx" if suffix == ".docx" else "source")
            item["status"] = "indexed"
        inventory.append(item)
    for doc in documents.values():
        doc.text = redactor.clean(doc.text)
        doc.facts = ast_facts(doc.text, doc.path)
    if not documents:
        raise AnalysisError("No supported project text")
    return Project(
        root, commit, documents, inventory, hasher.hexdigest(), chunk_documents(documents, chunk_chars)
    )


def compact_index(project):
    return {
        "commit": project.commit,
        "fingerprint": project.fingerprint,
        "files": project.inventory,
        "facts": {p: d.facts for p, d in project.documents.items() if d.facts},
        "chunks_total": len(project.chunks),
    }


def dump_context(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
