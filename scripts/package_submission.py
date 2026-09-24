"""Package source and a completed real run; never include .env, .git or virtual environments."""

import argparse
import json
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    required = ["report.json", "report.md", "execution.log", "metrics.json"]
    if args.output.exists():
        parser.error("Output archive already exists; choose a new name")
    if not all((args.run / name).is_file() for name in required):
        parser.error("A complete real run with JSON, Markdown, log and metrics is required")
    report = json.loads((args.run / "report.json").read_text(encoding="utf-8"))
    if report.get("exit_code") not in (0, 1) or report.get("result") not in ("pass", "fail"):
        parser.error("Incomplete assessment cannot be packaged as a completed submission")
    if report.get("model", "").startswith("MOCK") or report.get("usage", {}).get("total_tokens", 0) <= 0:
        parser.error("Synthetic or unmeasured run is not a real DeepSeek assessment")
    sources = []
    for folder in ("kmg_agent", "tests", "scripts", "docs", ".github"):
        sources.extend(
            p
            for p in (root / folder).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        )
    sources.extend(
        root / name
        for name in ("README.md", "pyproject.toml", "requirements.lock", ".env.example", ".gitignore")
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sources:
            archive.write(path, "source/" + path.relative_to(root).as_posix())
        for name in required + ["inventory.json"]:
            path = args.run / name
            if path.is_file():
                archive.write(path, "assessment/" + name)
        archive.writestr("TARGET_COMMIT.txt", report["commit"] + "\n")
    print(f"Created {args.output}; verify secret hygiene and attach genuine CI evidence before submission")


if __name__ == "__main__":
    main()
