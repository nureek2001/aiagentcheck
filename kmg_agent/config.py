"""Explicit configuration; no dotenv execution, interpolation or implicit target .env reads."""

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip().replace("_", "").isalnum():
            raise ValueError("Invalid .env entry")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@dataclass(frozen=True)
class Settings:
    key: str
    model: str = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    request_timeout: float = 120
    retries: int = 2
    chunk_chars: int = 90000
    context_chars: int = 800000
    max_tokens: int = 8000000
    max_requests: int = 250

    @classmethod
    def from_env(cls):
        value = cls(
            key=os.environ.get("DEEPSEEK_API_KEY", "").strip(),
            model=os.environ.get("DEEPSEEK_MODEL", "deepseek-flash"),
            base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            request_timeout=float(os.environ.get("DEEPSEEK_TIMEOUT", "120")),
            retries=int(os.environ.get("DEEPSEEK_RETRIES", "2")),
            max_tokens=int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8000000")),
            max_requests=int(os.environ.get("DEEPSEEK_MAX_REQUESTS", "250")),
        )
        url = urlparse(value.base_url)
        if url.scheme != "https" or url.hostname != "api.deepseek.com" or url.username or url.password:
            raise ValueError("Only the official HTTPS DeepSeek API is supported")
        if not value.key:
            raise ValueError("DEEPSEEK_API_KEY is empty; set it in .env or the environment")
        if not 1 <= value.request_timeout <= 300 or not 0 <= value.retries <= 4:
            raise ValueError("Invalid timeout or retry count")
        if value.max_tokens < 1000 or not 1 <= value.max_requests <= 2000:
            raise ValueError("Invalid API budget")
        return value
