"""Safe, atomic artifacts and deterministic Markdown rendering."""

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema


def write_json(path: Path, value, redactor):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(redactor.object(value), ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def markdown(report):
    def esc(s):
        return str(s).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        "# Отчёт проверки информационной безопасности",
        "",
        f"**Результат:** {report['result']} · **Код завершения:** {report['exit_code']}",
        "",
        f"Коммит: `{report['commit']}`",
        f"Модель: `{report['model']}`",
        "",
        f"Начало: {report['started_at']}",
        f"Окончание: {report['finished_at']}",
        f"Длительность: {report['duration_seconds']:.2f} с",
        "",
        f"Нарушений ИБ: **{len(report['findings'])}**. Дополнительных: **{len(report['additional_findings'])}**.",
        "",
        "## Проверенные требования",
        "",
        "| Требование | Статус | Находок | Обоснование |",
        "|---|---|---:|---|",
    ]
    for entry in report["requirements"]:
        lines.append(
            f"| {entry['id']} | {entry['status']} | {entry['finding_count']} | {esc(entry['reason'])} |"
        )
    for title, key in (
        ("Нарушения обязательных требований", "findings"),
        ("Дополнительные замечания — не блокируют пайплайн", "additional_findings"),
    ):
        lines.extend(["", "## " + title, ""])
        if not report[key]:
            lines.append("Подтверждённых находок нет. Полноту проверки определяют статусы выше.")
        for finding in report[key]:
            lines.extend(
                [
                    "",
                    f"### {esc(finding['requirement'])}: {esc(finding['title'])}",
                    "",
                    f"Критичность: **{finding['severity']}** · ID: `{finding['id']}`",
                    "",
                    esc(finding["requirement_text"]),
                    "",
                    esc(finding["reason"]),
                    "",
                    "**Рекомендация:** " + esc(finding["recommendation"]),
                    "",
                ]
            )
            for evidence in finding["evidence"]:
                lines.extend(
                    [
                        f"`{esc(evidence['path'])}` — {evidence['locator']}",
                        "",
                        # Indented code prevents untrusted backticks from breaking fences.
                        *["    " + line for line in evidence["snippet"].splitlines()],
                        "",
                    ]
                )
    lines.extend(
        [
            "",
            "## Покрытие и ресурсы",
            "",
            f"Файлов: {report['coverage']['files_total']}; текстовых: {report['coverage']['files_indexed']}.",
            f"Фрагментов: {report['coverage']['chunks_analysed']}/{report['coverage']['chunks_total']}.",
            f"API-запросов: {report['usage']['requests']}; токенов: {report['usage']['total_tokens']}.",
            "Полная инвентаризация и исключения находятся в JSON.",
            "",
            "## Ограничения",
            "",
        ]
    )
    lines.extend("- " + esc(x) for x in report["limitations"])
    return "\n".join(lines) + "\n"


def finalize(report, output, redactor, started, code=None):
    from .engine import decision, resource

    report["started_at"] = started.isoformat()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["duration_seconds"] = max(0, (datetime.now(timezone.utc) - started).total_seconds())
    report["exit_code"] = decision(report) if code is None else code
    report["result"] = {0: "pass", 1: "fail", 2: "incomplete"}[report["exit_code"]]
    report["finding_count"] = len(report["findings"])
    report["violated_requirements"] = sorted({f["requirement"] for f in report["findings"]})
    cleaned = redactor.object(report)
    jsonschema.validate(cleaned, json.loads(resource("report.schema.json")))
    write_json(output / "report.json", cleaned, redactor)
    (output / "report.md").write_text(markdown(cleaned), encoding="utf-8")
    return cleaned
