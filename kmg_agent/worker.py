"""Isolated worker: the parent process enforces a hard wall-clock deadline."""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .client import DeepSeek
from .config import Settings
from .engine import Engine
from .errors import AnalysisError, DeadlineError, ProviderError
from .project import compact_index, inspect_project
from .redaction import Redactor
from .reporting import finalize, write_json
from .progress import Progress


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--started", required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    output = Path(args.output)
    settings = Settings.from_env()
    redactor = Redactor([settings.key])
    client, engine = None, None
    progress = Progress(output, redactor)
    started = datetime.fromisoformat(args.started)
    try:
        progress.emit("Сбор файлов", stage="inventory")
        project = inspect_project(Path(args.repo), redactor, settings.chunk_chars)
        write_json(output / "inventory.json", compact_index(project), redactor)
        client = DeepSeek(settings, redactor, args.deadline)
        engine = Engine(
            project,
            client,
            checkpoint=progress.checkpoint,
            progress=progress.emit,
            workers=args.workers,
            cache_dir=args.cache_dir,
        )
        report = engine.run()
        progress.emit("Проверка неизменности исходников", stage="snapshot")
        # Detect concurrent modifications; never certify a different tree than the recorded snapshot.
        recheck = inspect_project(project.root, redactor, settings.chunk_chars)
        if recheck.commit != project.commit or recheck.fingerprint != project.fingerprint:
            raise AnalysisError("Target changed during analysis")
        report = finalize(report, output, redactor, started)
        progress.emit("Отчёт сохранён", stage="finished", status="completed", exit_code=report["exit_code"])
        write_json(
            output / "metrics.json",
            {
                "duration_seconds": report["duration_seconds"],
                "usage": report["usage"],
                "model": settings.model,
            },
            redactor,
        )
        return report["exit_code"]
    except ProviderError as exc:
        progress.emit("Ошибка провайдера", stage="error", status="completed", exit_code=2)
        # TZ 4.7.3: external-service failure produces diagnostics, NOT an assessment report.
        for name in ("checkpoint.json", "report.json", "report.md"):
            (output / name).unlink(missing_ok=True)
        write_json(
            output / "error.json",
            {
                "exit_code": 2,
                "kind": "provider_error",
                "message": str(exc),
                "usage": dict(client.usage) if client else {},
            },
            redactor,
        )
        print("Provider error; assessment report not produced (TZ 4.7.3)", flush=True)
        return 2
    except (AnalysisError, DeadlineError, OSError, ValueError) as exc:
        progress.emit("Проверка не завершена", stage="error", status="completed", exit_code=2)
        message = str(exc) if isinstance(exc, (AnalysisError, DeadlineError)) else "Local processing failed"
        write_json(
            output / "error.json", {"exit_code": 2, "kind": type(exc).__name__, "message": message}, redactor
        )
        if engine:
            engine.report["limitations"].append(message)
            engine.report["usage"] = dict(client.usage)
            finalize(engine.report, output, redactor, started, code=2)
        print("Analysis incomplete; exit_code=2", flush=True)
        return 2
    except Exception:
        progress.emit("Внутренняя ошибка", stage="error", status="completed", exit_code=2)
        # Never print exception repr/tracebacks containing source or provider payloads.
        write_json(
            output / "error.json",
            {
                "exit_code": 2,
                "kind": "internal_error",
                "message": "Unexpected internal error; assessment incomplete",
            },
            redactor,
        )
        for name in ("report.json", "report.md"):
            (output / name).unlink(missing_ok=True)
        print("Internal error; exit_code=2", flush=True)
        return 2
    finally:
        # Active threads may be completing network calls after one failed: parent deadline still applies.
        if client:
            write_json(
                output / "metrics.json",
                {
                    "duration_seconds": (datetime.now(timezone.utc) - started).total_seconds(),
                    "usage": dict(client.usage),
                    "model": settings.model,
                    "note": "Usage recorded before worker shutdown; in-flight failed requests may not report tokens",
                },
                redactor,
            )
            try:
                client.close()
            except RuntimeError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
