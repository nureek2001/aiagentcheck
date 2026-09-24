"""Map all chunks, assess each requirement with bounded retrieval, verify and gate."""

import hashlib
import json
import time
import re
from pathlib import Path
import jsonschema
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.resources import files

from .contracts import IDS, MAP, REVIEW, VERIFY
from .errors import AnalysisError, DeadlineError, OutputLimitError
from .project import compact_index, dump_context


def resource(name):
    return files("kmg_agent").joinpath("resources", name).read_text(encoding="utf-8")


def catalogue():
    return json.loads(resource("requirements.json"))


def base_report(project, model):
    from datetime import datetime, timezone

    return {
        "schema_version": "1.0",
        "agent_version": "1.0.0",
        "commit": project.commit,
        "source_fingerprint": project.fingerprint,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "duration_seconds": 0,
        "result": "incomplete",
        "exit_code": 2,
        "model": model,
        "findings": [],
        "additional_findings": [],
        "rejected_candidates": [],
        "requirements": [
            {
                "id": r["id"],
                "text": r["text"],
                "status": "not_checked",
                "reason": "Проверка ещё не выполнена",
                "evidence": [],
                "finding_count": 0,
            }
            for r in catalogue()
            if r["id"] in IDS
        ],
        "coverage": {
            "files_total": len(project.inventory),
            "files_indexed": len(project.documents),
            "chunks_total": len(project.chunks),
            "chunks_analysed": 0,
            "extra_checked": False,
            "inventory": project.inventory,
        },
        "usage": {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "limitations": [
            "Статический анализ и выводы LLM; приложение не запускалось.",
            "Сертификация, инфраструктура вне репозитория и реальные права ОС не подтверждаются.",
            "Секреты маскируются эвристически; значения заменены на [REDACTED].",
        ],
    }


def decision(report):
    completed = report["coverage"]["chunks_analysed"] == report["coverage"]["chunks_total"]
    completed = completed and report["coverage"]["extra_checked"]
    completed = completed and all(r["status"] in {"pass", "fail"} for r in report["requirements"])
    if not completed:
        return 2
    return 1 if report["findings"] else 0


class Engine:
    def __init__(self, project, client, checkpoint=lambda _: None, progress=print, workers=2, cache_dir=None):
        self.project, self.client, self.checkpoint, self.progress = project, client, checkpoint, progress
        self.workers = workers
        self.report = base_report(project, client.settings.model)
        self.system = resource("system.md")
        self.observations = []
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def save(self):
        self.report["usage"] = dict(self.client.usage)
        self.checkpoint(self.report)

    def check_time(self):
        if time.monotonic() >= self.client.deadline:
            raise DeadlineError("Overall analysis deadline reached")

    def run(self):
        self.save()
        # Bounded concurrency. API errors propagate: they are never converted to 'pass'.
        pool = ThreadPoolExecutor(max_workers=self.workers)
        try:
            pending = {pool.submit(self.map_chunk, c): c["id"] for c in self.project.chunks}
            for future in as_completed(pending):
                self.check_time()
                self.observations.extend(future.result())
                self.report["coverage"]["chunks_analysed"] += 1
                self.progress(
                    f"Context {self.report['coverage']['chunks_analysed']}/{len(self.project.chunks)}"
                )
                self.save()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        self.observations.sort(
            key=lambda o: (o["requirement"], o["evidence"][0]["path"], o["evidence"][0]["start"], o["fact"])
        )
        for requirement in catalogue():
            self.check_time()
            self.progress(f"Review {requirement['id']}")
            self.review(requirement)
            self.save()
        self.report["exit_code"] = decision(self.report)
        return self.report

    def map_chunk(self, chunk, depth=0):
        cache_path = None
        if self.cache_dir:
            identity = dump_context(
                {
                    "chunk": chunk,
                    "model": self.client.settings.model,
                    "system": self.system,
                    "map_prompt": resource("map.md"),
                    "requirements": catalogue(),
                    "schema": MAP,
                }
            )
            cache_path = self.cache_dir / (hashlib.sha256(identity.encode()).hexdigest() + ".json")
            if cache_path.is_file() and time.time() - cache_path.stat().st_mtime < 86400:
                try:
                    cached = json.loads(cache_path.read_text(encoding="utf-8"))
                    jsonschema.validate(cached, MAP)
                    self.validate_map(cached, chunk)
                    return cached["observations"]
                except (ValueError, OSError, jsonschema.ValidationError, AnalysisError):
                    pass
        observations = self.analyse_chunk(chunk, depth)
        if cache_path:
            from .reporting import write_json

            write_json(cache_path, {"observations": observations}, self.client.redactor)
        return observations

    def validate_map(self, result, chunk):
        for obs in result["observations"]:
            for ref in obs["evidence"]:
                self.project.evidence(ref)
                # A range may legitimately span adjacent supplied segments of the SAME file.
                cursor = ref["start"]
                for segment in sorted(chunk["segments"], key=lambda s: s["start"]):
                    if segment["path"] == ref["path"] and segment["start"] <= cursor <= segment["end"]:
                        cursor = segment["end"] + 1
                if cursor <= ref["end"]:
                    raise AnalysisError(
                        f"Map evidence outside chunk {chunk['id']}: {ref['path']}:{ref['start']}-{ref['end']}"
                    )

    def subdivide_chunk(self, chunk, depth):
        if depth >= 4:
            raise AnalysisError(
                f"Map recovery exhausted for chunk {chunk['id']}; outside or oversized evidence"
            )
        segments = chunk["segments"]
        if len(segments) > 1:
            middle = len(segments) // 2
            halves = [segments[:middle], segments[middle:]]
        else:
            segment = segments[0]
            lines = segment["text"].splitlines()
            if len(lines) < 2:
                raise AnalysisError(f"Cannot recover evidence outside indivisible chunk {chunk['id']}")
            middle = len(lines) // 2
            halves = []
            for group in (lines[:middle], lines[middle:]):
                first, last = re.match(r"(\d+):", group[0]), re.match(r"(\d+):", group[-1])
                if not first or not last:
                    raise AnalysisError("Cannot safely subdivide numbered source context")
                halves.append(
                    [{**segment, "start": int(first[1]), "end": int(last[1]), "text": "\n".join(group)}]
                )
        return [
            observation
            for half in halves
            for observation in self.map_chunk({"id": chunk["id"], "segments": half}, depth + 1)
        ]

    def analyse_chunk(self, chunk, depth=0):
        self.check_time()
        payload = {
            "requirements": catalogue(),
            "chunk": chunk,
            "allowed_evidence_ranges": [
                {k: segment[k] for k in ("path", "start", "end")} for segment in chunk["segments"]
            ],
        }
        for attempt in range(3):
            try:
                result = self.client.ask(self.system + resource("map.md"), payload, MAP)
            except OutputLimitError:
                return self.subdivide_chunk(chunk, depth)
            try:
                self.validate_map(result, chunk)
                return result["observations"]
            except AnalysisError as exc:
                if attempt == 2:
                    return self.subdivide_chunk(chunk, depth)
                payload["correction"] = {
                    "error": str(exc),
                    "previous_observations": result["observations"],
                    "instruction": "Your evidence was invalid. Reanalyse using allowed_evidence_ranges. Line numbers are the numeric PREFIX before the colon in source text, not numbers inside the document. Cite only ranges fully present in this chunk. For DOCX use the supplied paragraph numbers. Remove observations unsupported by this chunk; never invent or renumber lines.",
                }
        raise AnalysisError("Evidence repair exhausted")

    def review(self, requirement):
        rid = requirement["id"]
        observations = [o for o in self.observations if o["requirement"] == rid]
        # All per-requirement map observations are retained. Original source is budgeted and retrievable.
        index = compact_index(self.project)
        payload = {
            "requirement": requirement,
            "inventory": index["files"],
            "topology": {
                p: facts
                for p, facts in index["facts"].items()
                if any(f["type"] == "route" for f in facts)
                or p.endswith(("settings.py", "apps.py", "middleware.py"))
            },
            "observations": observations,
            "source": [],
        }
        if rid == "EXTRA":
            payload["already_reported_mandatory_findings"] = [
                {k: f[k] for k in ("requirement", "title", "root_cause")} for f in self.report["findings"]
            ]
            payload["scope_note"] = (
                "Report only additional specification issues. Do not repeat mandatory findings "
                "already listed above under EXTRA. An issue with the same cause and operation is a duplicate."
            )
        # Keep shared enforcement bodies available even when a map observation cites only a call site.
        # This is based on common component names, not pre-labelled vulnerabilities or target paths.
        component_names = {
            "settings.py",
            "urls.py",
            "middleware.py",
            "access.py",
            "audit.py",
            "apps.py",
            "views.py",
            "local_acl.py",
            "collector.py",
            "serve.py",
            "setup_local.py",
            "storage.py",
            "hashers.py",
            "models.py",
        }
        payload["shared_components"] = []
        for path, doc in self.project.documents.items():
            if Path(path).name in component_names and len(doc.text) <= 30000:
                evidence = self.project.evidence({"path": path, "start": 1, "end": len(doc.lines())})
                if (
                    len(dump_context(payload)) + len(dump_context(evidence))
                    < self.client.settings.context_chars - 40000
                ):
                    payload["shared_components"].append(evidence)
        if len(dump_context(payload)) > self.client.settings.context_chars - 12000:
            raise AnalysisError("Requirement summaries exceed context budget; review cannot be complete")
        seen = set()
        for obs in observations:
            for ref in obs["evidence"]:
                key = (ref["path"], ref["start"], ref["end"])
                if key in seen:
                    continue
                seen.add(key)
                evidence = self.project.evidence(ref)
                if (
                    len(dump_context(payload)) + len(dump_context(evidence))
                    < self.client.settings.context_chars - 120000
                ):
                    payload["source"].append(evidence)
        result = None
        for _ in range(4):
            self.check_time()
            result = self.client.ask(self.system + resource("review.md"), payload, REVIEW)
            if result["status"] != "needs_context":
                if result["requests"]:
                    raise AnalysisError("Final assessment contains unresolved source requests")
                break
            if not result["requests"]:
                raise AnalysisError("Model requested context without specifying ranges")
            requested = self.project.context(result["requests"])
            # Replacing source keeps full observations and ensures requested evidence fits without silent truncation.
            payload["source"] = requested
            payload["previous_assessment"] = {"reason": result["reason"]}
        if result["status"] == "needs_context":
            result["status"] = "inconclusive"
        references = self.project.context(result["evidence"])
        if result["status"] == "pass" and (not references or result["findings"]):
            raise AnalysisError("A pass requires positive evidence and no findings")
        if result["status"] == "fail" and not result["findings"]:
            raise AnalysisError("A failure requires findings")
        confirmed, uncertain = [], result["status"] == "inconclusive"
        for item in result["findings"]:
            self.progress(f"Verify {rid}")
            evidence = self.project.context(item["evidence"])
            finding_paths = {ref["path"] for ref in item["evidence"]}
            verification_payload = {
                "requirement": requirement,
                "topology": payload["topology"],
                "shared_components": payload["shared_components"],
                "related_observations": [
                    o for o in observations if any(ref["path"] in finding_paths for ref in o["evidence"])
                ],
                "finding": item,
                "finding_source": evidence,
            }
            verification = self.client.ask(
                self.system + resource("verify.md"),
                verification_payload,
                VERIFY,
            )
            if verification["verdict"] != "confirmed":
                self.report["rejected_candidates"].append(
                    {
                        "requirement": rid,
                        "title": item["title"],
                        "verdict": verification["verdict"],
                        "reason": verification["reason"],
                    }
                )
                # Rejection of a finding is not proof of compliance. Require a fresh review next run.
                uncertain = True
                continue
            primary = item["evidence"][0]
            identity = f"{rid}:{primary['path']}:{primary['start']}:{item['root_cause'].strip().lower()}"
            finding = {
                "id": hashlib.sha256(identity.encode()).hexdigest()[:12],
                "requirement": rid,
                "requirement_text": requirement["text"],
                **{k: item[k] for k in ("title", "severity", "reason", "recommendation", "root_cause")},
                "evidence": evidence,
                "verification": verification["reason"],
            }
            if finding["id"] not in {f["id"] for f in confirmed}:
                confirmed.append(finding)
        # One confirmed violation proves noncompliance even if a separate candidate was rejected.
        # Without a confirmed violation, rejected/uncertain candidates still cannot imply a pass.
        status = "fail" if confirmed else ("inconclusive" if uncertain else result["status"])
        assessment_reason = result["reason"]
        if status == "fail":
            assessment_reason = "Подтверждённые нарушения: " + "; ".join(f["title"] for f in confirmed)
        elif status == "inconclusive" and uncertain:
            assessment_reason = (
                "Недостаточно подтверждённых доказательств для окончательного вывода. "
                + " ".join(r["reason"] for r in self.report["rejected_candidates"] if r["requirement"] == rid)
            )
        if rid == "EXTRA":
            self.report["additional_findings"].extend(confirmed)
            self.report["coverage"]["extra_checked"] = status in {"pass", "fail"}
            if not self.report["coverage"]["extra_checked"]:
                self.report["limitations"].append(
                    "Проверка дополнительных требований не завершена: " + result["reason"]
                )
        else:
            self.report["findings"].extend(confirmed)
            entry = next(r for r in self.report["requirements"] if r["id"] == rid)
            entry.update(
                status=status, reason=assessment_reason, evidence=references, finding_count=len(confirmed)
            )
