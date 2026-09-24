"""Conservative text redaction, applied before API transmission and artifact writes."""

import re

PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END (?:[A-Z ]*PRIVATE KEY)-----"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{15,}|github_pat_[A-Za-z0-9_]{15,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\b(?:Training-2026!|Service-2026!)[^\s\"'`,|<]+"),
    re.compile(
        r"(?im)(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[\"']?\s*[:=]\s*[\"']([^\"'\n]+)[\"']"
    ),
    re.compile(r"(?m)^\s*(?:[A-Z_]*(?:KEY|TOKEN|PASSWORD|SECRET))\s*=\s*([A-Za-z0-9_+/-]{8,})\s*(?:#.*)?$"),
    re.compile(r"(?i)(?:set_password|check_password)\(\s*[\"']([^\"'\n]+)[\"']"),
]


class Redactor:
    def __init__(self, known=()):
        self.known = {v for v in known if isinstance(v, str) and len(v) >= 4}

    def discover(self, text: str):
        for pattern in PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1) if pattern.groups else match.group(0)
                if len(value) >= 4:
                    self.known.add(value)

    def clean(self, text: str) -> str:
        self.discover(text)
        for value in sorted(self.known, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]" + "\n" * value.count("\n"))
        return text

    def object(self, value):
        if isinstance(value, str):
            return self.clean(value)
        if isinstance(value, list):
            return [self.object(x) for x in value]
        if isinstance(value, dict):
            return {self.clean(str(k)): self.object(v) for k, v in value.items()}
        return value
