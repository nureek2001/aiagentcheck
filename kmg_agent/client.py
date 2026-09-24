"""Bounded DeepSeek calls. Responses are untrusted and validated against JSON Schema."""

import json
import time
import threading

import httpx
import jsonschema

from .errors import AnalysisError, DeadlineError, ProviderError, OutputLimitError, BudgetError


class DeepSeek:
    def __init__(self, settings, redactor, deadline, transport=None):
        self.settings, self.redactor, self.deadline = settings, redactor, deadline
        self.http = httpx.Client(transport=transport, follow_redirects=False, trust_env=False)
        self.lock = threading.Lock()
        self.budget_used = 0
        self.budget_reserved = 0
        self.attempts = 0
        self.usage = {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def budget(self):
        with self.lock:
            return {"max_tokens": self.settings.max_tokens, "max_requests": self.settings.max_requests,
                    "charged_or_estimated_tokens": self.budget_used, "reserved_tokens": self.budget_reserved,
                    "attempts": self.attempts, "reported_tokens": self.usage["total_tokens"]}

    def reserve(self, body):
        # UTF-8 byte count plus output allowance is intentionally conservative, not a price estimate.
        estimate = len(json.dumps(body["messages"], ensure_ascii=False).encode("utf-8")) + body["max_tokens"] + 1024
        with self.lock:
            if self.attempts >= self.settings.max_requests or self.budget_used + self.budget_reserved + estimate > self.settings.max_tokens:
                raise BudgetError("API budget exhausted before the next request; assessment incomplete")
            self.attempts += 1
            self.usage["requests"] += 1
            self.budget_reserved += estimate
        return estimate

    def settle(self, estimate, actual=None):
        with self.lock:
            self.budget_reserved -= estimate
            self.budget_used += actual if actual is not None else estimate

    def close(self):
        self.http.close()

    def ask(self, system, payload, schema):
        instruction = system + "\nReturn JSON only, conforming to this schema:\n" + json.dumps(schema)
        content = self.redactor.clean(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        if len(content) > self.settings.context_chars:
            phase = (
                "verification" if "finding" in payload else "review" if "requirement" in payload else "map"
            )
            raise AnalysisError(
                f"{phase} context exceeds budget ({len(content)} > {self.settings.context_chars} characters); nothing truncated"
            )
        body = {
            "model": self.settings.model,
            "messages": [{"role": "system", "content": instruction}, {"role": "user", "content": content}],
            "response_format": {"type": "json_object"},
            "max_tokens": 16000,
            "thinking": {"type": "disabled"},
            "temperature": 0,
        }
        for attempt in range(self.settings.retries + 1):
            remaining = self.deadline - time.monotonic()
            if remaining <= 1:
                raise DeadlineError("Overall analysis deadline reached")
            estimate = self.reserve(body)
            try:
                response = self.http.post(
                    self.settings.base_url + "/chat/completions",
                    json=body,
                    headers={"Authorization": "Bearer " + self.settings.key},
                    timeout=min(self.settings.request_timeout, remaining),
                )
            except httpx.TransportError as exc:
                self.settle(estimate)
                if attempt == self.settings.retries:
                    raise ProviderError("DeepSeek network error or request timeout") from exc
            else:
                actual = None
                if response.status_code == 200:
                    try:
                        reported = response.json().get("usage", {}).get("total_tokens")
                        if isinstance(reported, int) and not isinstance(reported, bool) and reported >= 0:
                            actual = reported
                    except (ValueError, AttributeError):
                        pass
                self.settle(estimate, actual)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        usage = data.get("usage", {})
                        with self.lock:
                            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                                self.usage[key] += int(usage.get(key, 0))
                        choice = data["choices"][0]
                        if choice["finish_reason"] == "length":
                            raise OutputLimitError("DeepSeek output token limit reached")
                        if choice["finish_reason"] != "stop":
                            raise AnalysisError("DeepSeek response was incomplete")
                        result = json.loads(choice["message"]["content"])
                        jsonschema.validate(result, schema)
                        return self.redactor.object(result)
                    except (KeyError, IndexError, ValueError, TypeError, jsonschema.ValidationError) as exc:
                        if isinstance(exc, jsonschema.ValidationError):
                            correction = {
                                "validator": exc.validator,
                                "path": list(exc.absolute_path),
                                "expected": exc.validator_value,
                                "actual": str(exc.instance)[:600],
                            }
                            safe_reason = f"schema validator {exc.validator} at {list(exc.absolute_path)}"
                        else:
                            correction = {
                                "error": "Response must be a JSON object with exactly the requested schema"
                            }
                            safe_reason = "invalid JSON or response envelope"
                        if attempt == self.settings.retries:
                            raise AnalysisError(
                                "DeepSeek returned invalid structured output: " + safe_reason
                            ) from exc
                        body["messages"].append(
                            {
                                "role": "user",
                                "content": "Your previous response did not conform to the required JSON schema. Reanalyse the original input and return a complete corrected JSON object. Validation details: "
                                + json.dumps(self.redactor.object(correction), ensure_ascii=False),
                            }
                        )
                        continue
                if (
                    response.status_code not in {408, 429, 500, 502, 503, 504}
                    or attempt == self.settings.retries
                ):
                    raise ProviderError(f"DeepSeek HTTP {response.status_code}; response body suppressed")
            delay = min(2**attempt, 8)
            if time.monotonic() + delay >= self.deadline:
                raise DeadlineError("Overall analysis deadline reached during retries")
            time.sleep(delay)
        raise ProviderError("DeepSeek request failed")
