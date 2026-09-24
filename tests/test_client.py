import json
import time

import httpx
import pytest

from kmg_agent.client import DeepSeek
from kmg_agent.config import Settings
from kmg_agent.contracts import MAP
from kmg_agent.errors import AnalysisError, DeadlineError, ProviderError
from kmg_agent.redaction import Redactor


def client(handler, **kwargs):
    return DeepSeek(
        Settings(key="sk-test-secret-123456789", retries=0),
        Redactor(["sk-test-secret-123456789"]),
        kwargs.get("deadline", time.monotonic() + 60),
        transport=httpx.MockTransport(handler),
    )


def response(content, finish="stop"):
    return httpx.Response(
        200,
        json={
            "choices": [{"finish_reason": finish, "message": {"content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


def test_real_request_contract_and_usage():
    def handler(request):
        body = json.loads(request.content)
        assert str(request.url) == "https://api.deepseek.com/chat/completions"
        assert body["response_format"] == {"type": "json_object"}
        assert "sk-test-secret-123456789" not in body["messages"][1]["content"]
        return response('{"observations":[]}')

    api = client(handler)
    assert api.ask("Return JSON", {"code": "sk-test-secret-123456789"}, MAP) == {"observations": []}
    assert api.usage["total_tokens"] == 15
    api.close()


@pytest.mark.parametrize("status", [401, 429, 500])
def test_api_error_does_not_leak_body(status):
    api = client(lambda _: httpx.Response(status, text="sensitive body"))
    with pytest.raises(ProviderError) as error:
        api.ask("Return JSON", {}, MAP)
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize(
    "body,finish", [("not json", "stop"), ("{}", "stop"), ('{"observations":[]}', "length")]
)
def test_invalid_or_truncated_output_fails(body, finish):
    api = client(lambda _: response(body, finish))
    with pytest.raises(AnalysisError):
        api.ask("Return JSON", {}, MAP)


def test_deadline_prevents_request():
    def never(_):
        pytest.fail("No request after deadline")

    with pytest.raises(DeadlineError):
        client(never, deadline=time.monotonic() - 1).ask("JSON", {}, MAP)


def test_protocol_error_is_a_provider_failure():
    def broken(_):
        raise httpx.RemoteProtocolError("untrusted response detail")

    with pytest.raises(ProviderError) as exc:
        client(broken).ask("JSON", {}, MAP)
    assert "untrusted" not in str(exc.value)


def test_retry_on_429_is_bounded(monkeypatch):
    calls = []

    def handler(_):
        calls.append(1)
        return httpx.Response(429) if len(calls) == 1 else response('{"observations":[]}')

    monkeypatch.setattr("kmg_agent.client.time.sleep", lambda _: None)
    api = DeepSeek(
        Settings(key="synthetic-key", retries=1),
        Redactor(),
        time.monotonic() + 60,
        transport=httpx.MockTransport(handler),
    )
    assert api.ask("JSON", {}, MAP) == {"observations": []}
    assert len(calls) == 2


def test_schema_error_requests_a_corrected_response():
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        return response('{"wrong": []}') if len(calls) == 1 else response('{"observations":[]}')

    api = DeepSeek(
        Settings(key="synthetic-key", retries=1),
        Redactor(),
        time.monotonic() + 60,
        transport=httpx.MockTransport(handler),
    )
    assert api.ask("JSON", {}, MAP) == {"observations": []}
    assert len(calls) == 2
    assert "Validation details" in calls[1]["messages"][-1]["content"]
