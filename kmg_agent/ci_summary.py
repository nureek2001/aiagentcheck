"""Compact GitHub job summary; no untrusted source or model Markdown rendered."""

import os
import sys
from pathlib import Path

from .dashboard import read_json


def summary(directory):
    report = read_json(directory / "report.json")
    if not report:
        return (
            "## Security assessment incomplete\n\nNo final assessment. Download diagnostics from Artifacts.\n"
        )
    code = report.get("exit_code", 2)
    code = code if code in (0, 1, 2) else 2
    count = len(report.get("findings", []))
    result = {0: "PASS", 1: "FAIL", 2: "INCOMPLETE"}[code]
    lines = [
        "## Security assessment",
        "",
        f"**Result:** {result}",
        f"**Exit code:** {code} · **Mandatory findings:** {count}",
        "",
        "| Requirement | Status |",
        "|---|---|",
    ]
    for entry in report.get("requirements", []):
        rid = entry.get("id")
        if rid not in {f"ИБ-{i:02d}" for i in range(1, 9)}:
            continue
        status = entry.get("status")
        status = status if status in {"pass", "fail", "inconclusive", "not_checked"} else "unknown"
        lines.append(f"| {rid} | {status} |")
    lines.extend(
        [
            "",
            "Download **security-assessment** in Artifacts and open **dashboard.html**.",
            "JSON, Markdown, progress and diagnostics are included. No target code was executed.",
        ]
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    content = summary(Path(sys.argv[1]))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(content)
    else:
        print(content)
