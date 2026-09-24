"""Machine-readable progress; no fabricated percentages or model reasoning."""

from datetime import datetime, timezone

from .reporting import write_json


class Progress:
    def __init__(self, output, redactor):
        self.output, self.redactor = output, redactor
        self.state = {"stage": "inventory", "message": "Сбор файлов", "status": "running"}

    def emit(self, message, **values):
        self.state.update(values, message=message, updated_at=datetime.now(timezone.utc).isoformat())
        if message.startswith("Context "):
            completed, total = map(int, message.split()[1].split("/"))
            self.state.update(stage="map", completed=completed, total=total)
        elif message.startswith("Review "):
            self.state.update(stage="review", requirement=message.removeprefix("Review "))
        elif message.startswith("Verify "):
            self.state.update(stage="verify", requirement=message.removeprefix("Verify "))
        write_json(self.output / "progress.json", self.state, self.redactor)
        print(message, flush=True)

    def checkpoint(self, report):
        write_json(self.output / "checkpoint.json", report, self.redactor)
