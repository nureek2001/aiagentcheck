"""Strict model contracts; report schema is shipped as a standalone resource."""

REF = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "start", "end"],
    "properties": {
        "path": {"type": "string", "minLength": 1},
        "start": {"type": "integer", "minimum": 1},
        "end": {"type": "integer", "minimum": 1},
    },
}
TEXT = {"type": "string", "minLength": 1, "maxLength": 6000}
REFS = {"type": "array", "items": REF, "minItems": 1, "maxItems": 16}
IDS = [f"ИБ-{i:02d}" for i in range(1, 9)]
FINDING = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "severity", "reason", "recommendation", "evidence", "root_cause"],
    "properties": {
        "title": TEXT,
        "severity": {"enum": ["critical", "high", "medium", "low"]},
        "reason": TEXT,
        "recommendation": TEXT,
        "evidence": REFS,
        "root_cause": TEXT,
    },
}
MAP = {
    "type": "object",
    "additionalProperties": False,
    "required": ["observations"],
    "properties": {
        "observations": {
            "type": "array",
            "maxItems": 256,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["requirement", "fact", "evidence"],
                "properties": {"requirement": {"enum": IDS + ["EXTRA"]}, "fact": TEXT, "evidence": REFS},
            },
        }
    },
}
REVIEW = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "reason", "evidence", "findings", "requests"],
    "properties": {
        "status": {"enum": ["pass", "fail", "inconclusive", "needs_context"]},
        "reason": TEXT,
        "evidence": {"type": "array", "items": REF, "maxItems": 24},
        "findings": {"type": "array", "items": FINDING, "maxItems": 40},
        "requests": {"type": "array", "items": REF, "maxItems": 24},
    },
}
VERIFY = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "reason"],
    "properties": {"verdict": {"enum": ["confirmed", "rejected", "uncertain"]}, "reason": TEXT},
}
