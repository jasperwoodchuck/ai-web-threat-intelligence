import io
import json
import logging
import pytest
from urllib.error import HTTPError, URLError

from app.ai.openrouter import ModelResponseError, OpenRouterProvider, ProviderRateLimitError, ProviderRequestError


class Response(io.BytesIO):
    status = 200

    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status
        self.headers = {"Content-Type": "application/json; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


VALID_INTERPRETATION = {
    "summary": "The message makes an urgent verification request.",
    "suspicious_indicators": ["Urgency language"],
    "evidence": ["The message requests immediate action."],
    "recommended_actions": ["Verify through an official contact channel."],
    "limitations": [],
    "confidence": 0.82,
}


def response(content: object, status: int = 200) -> Response:
    body = json.dumps(
        {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}
    ).encode()
    return Response(body, status)


def provider() -> OpenRouterProvider:
    return OpenRouterProvider("test-secret-key", "test-model")


def mock_response(monkeypatch, content: object, *, capture: dict | None = None) -> None:
    def fake_urlopen(request, timeout):
        if capture is not None:
            capture.update(request=request, timeout=timeout)
        return response(content)

    monkeypatch.setattr("app.ai.openrouter.urlopen", fake_urlopen)


def test_valid_structured_json_and_schema_request(monkeypatch, caplog) -> None:
    capture = {}
    mock_response(monkeypatch, json.dumps(VALID_INTERPRETATION), capture=capture)
    caplog.set_level(logging.INFO, logger="app.ai.openrouter")

    result = provider().explain("Untrusted message", [{"category": "urgency"}], [])

    assert result.status == "available"
    assert result.summary == VALID_INTERPRETATION["summary"]
    assert result.suspicious_indicators == ["Urgency language"]
    request_body = json.loads(capture["request"].data)
    assert request_body["response_format"]["type"] == "json_schema"
    assert request_body["response_format"]["json_schema"]["strict"] is True
    assert request_body["provider"]["require_parameters"] is True
    assert capture["timeout"] == 90.0
    assert "status=200" in caplog.text
    assert "structured output parsed" in caplog.text
    assert "test-secret-key" not in caplog.text


def test_parses_json_inside_markdown_fence(monkeypatch) -> None:
    mock_response(monkeypatch, f"```json\n{json.dumps(VALID_INTERPRETATION)}\n```")

    result = provider().explain("A message", [], [])

    assert result.status == "available"
    assert result.summary == VALID_INTERPRETATION["summary"]


def test_parses_json_encoded_as_a_string(monkeypatch) -> None:
    mock_response(monkeypatch, json.dumps(json.dumps(VALID_INTERPRETATION)))

    result = provider().explain("A message", [], [])

    assert result.status == "available"
    assert result.confidence == 0.82


def test_malformed_json_is_reported_as_malformed(monkeypatch, caplog) -> None:
    mock_response(monkeypatch, "not JSON")
    caplog.set_level(logging.WARNING, logger="app.ai.openrouter")

    result = provider().explain("A message", [], [])

    assert result.status == "malformed"
    assert "not valid JSON" in result.limitations[0]
    assert "structured output invalid" in caplog.text


def test_missing_required_fields_are_reported(monkeypatch) -> None:
    mock_response(monkeypatch, json.dumps({"summary": "Partial result"}))

    result = provider().explain("A message", [], [])

    assert result.status == "malformed"
    assert "required fields missing" in result.limitations[0]


def test_openrouter_http_error_is_unavailable_and_logged_without_secrets(monkeypatch, caplog) -> None:
    def fail(*_args, **_kwargs):
        raise HTTPError(
            "https://openrouter.ai/api/v1/chat/completions",
            429,
            "rate limited",
            {"Content-Type": "application/json"},
            io.BytesIO(b"provider error"),
        )

    monkeypatch.setattr("app.ai.openrouter.urlopen", fail)
    monkeypatch.setattr("app.ai.openrouter.time.sleep", lambda _seconds: None)
    caplog.set_level(logging.WARNING, logger="app.ai.openrouter")

    result = provider().explain("A message", [], [])

    assert result.status == "unavailable"
    assert "HTTP 429" in result.limitations[0]
    assert "status=429" in caplog.text
    assert "attempt=2 max_attempts=2" in caplog.text
    assert "temporarily unavailable due to rate limiting" in result.limitations[0]
    assert "test-secret-key" not in caplog.text


def test_interpretation_retry_after_then_success(monkeypatch) -> None:
    calls, waits = [], []
    def request(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise HTTPError("https://openrouter.ai/api/v1/chat/completions", 429, "rate limited", {"Retry-After": "30"}, io.BytesIO())
        return response(json.dumps(VALID_INTERPRETATION))
    monkeypatch.setattr("app.ai.openrouter.urlopen", request)
    monkeypatch.setattr("app.ai.openrouter.time.sleep", waits.append)
    result = provider().explain("A message", [], [])
    assert result.status == "available"
    assert len(calls) == 2 and waits == [1.5]


def test_interpretation_404_logs_sanitized_provider_body_and_request_context(monkeypatch, caplog) -> None:
    body = b'{"error":{"code":404,"message":"No endpoints found for this model. Bearer secret-token"}}'
    calls = []
    def not_found(*_args, **_kwargs):
        calls.append(1)
        raise HTTPError("https://openrouter.ai/api/v1/chat/completions", 404, "Not Found", {"Content-Type": "application/json"}, io.BytesIO(body))
    monkeypatch.setattr("app.ai.openrouter.urlopen", not_found)
    caplog.set_level(logging.INFO, logger="app.ai.openrouter")
    result = provider().explain("A message", [], [])
    assert result.status == "unavailable"
    assert len(calls) == 1
    assert "No endpoints found for this model" in caplog.text
    assert "Bearer <redacted>" in caplog.text
    assert "secret-token" not in caplog.text
    assert "request_id=" in caplog.text and "response_time_ms=" in caplog.text
    assert "method=POST" in caplog.text and "attempt=1 max_attempts=2" in caplog.text


def test_interpretation_timeout_is_reported_clearly_and_preserves_deterministic_analysis(monkeypatch, caplog) -> None:
    def timeout(*_args, **_kwargs):
        raise TimeoutError("socket timed out")

    monkeypatch.setattr("app.ai.openrouter.urlopen", timeout)
    caplog.set_level(logging.WARNING, logger="app.ai.openrouter")

    result = provider().explain("A message", [], [])

    assert result.status == "unavailable"
    assert "90 seconds" in result.limitations[0]
    assert "request timed out" in caplog.text
    assert "operation=interpretation" in caplog.text and "timeout_seconds=90.0" in caplog.text
    assert "request_id=" in caplog.text and "response_time_ms=" in caplog.text
    assert "test-secret-key" not in caplog.text


def test_wrapped_socket_timeout_is_reported_as_timeout(monkeypatch, caplog) -> None:
    monkeypatch.setattr(
        "app.ai.openrouter.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError(TimeoutError("socket timed out"))),
    )
    caplog.set_level(logging.WARNING, logger="app.ai.openrouter")

    result = provider().explain("A message", [], [])

    assert result.status == "unavailable"
    assert "did not respond within 90 seconds" in result.limitations[0]
    assert "request timed out" in caplog.text
    assert "operation=interpretation" in caplog.text and "response_time_ms=" in caplog.text


def test_image_and_text_inspection_use_same_configured_model(monkeypatch) -> None:
    captured_models = []
    file_response = {
        "extracted_text": "Visible notice",
        "content_type": "notification",
        "classification_confidence": 0.82,
        "classification_reasoning": "Notification layout detected.",
        "summary": "A notification is shown.",
        "indicators": [],
        "recommended_action": "Verify independently.",
        "limitations": [],
    }

    def fake_urlopen(request, timeout):
        captured_models.append(json.loads(request.data)["model"])
        return response(json.dumps(file_response))

    monkeypatch.setattr("app.ai.openrouter.urlopen", fake_urlopen)
    ai = OpenRouterProvider("shared-key", "shared-model")
    assert ai.inspect_text("Visible notice")["content_type"] == "notification"
    assert ai.inspect_image(bytes([137, 80, 78, 71, 13, 10, 26, 10]), "image/png")["content_type"] == "notification"
    assert captured_models == ["shared-model", "shared-model"]


def _image_error(code: int, headers: dict[str, str] | None = None):
    return HTTPError("https://openrouter.ai/api/v1/chat/completions", code, "provider failure", headers or {}, io.BytesIO(b"provider error"))


def test_image_analysis_200(monkeypatch) -> None:
    mock_response(monkeypatch, json.dumps({
        "extracted_text": "Visible notice", "content_type": "notification", "classification_confidence": 0.8,
        "classification_reasoning": "Notification", "summary": "Notice", "indicators": [],
        "recommended_action": "Verify independently", "limitations": [],
    }))
    assert provider().inspect_image(b"image", "image/png")["extracted_text"] == "Visible notice"


def test_image_rate_limit_retries_once_and_honors_bounded_retry_after(monkeypatch, caplog) -> None:
    calls, waits = [], []
    def request(*_args, **_kwargs):
        calls.append(1)
        raise _image_error(429, {"Retry-After": "30", "Content-Type": "application/json"})
    monkeypatch.setattr("app.ai.openrouter.urlopen", request)
    monkeypatch.setattr("app.ai.openrouter.time.sleep", waits.append)
    caplog.set_level(logging.WARNING, logger="app.ai.openrouter")
    with pytest.raises(ProviderRateLimitError) as error:
        provider().inspect_image(b"image", "image/png")
    assert len(calls) == 2
    assert waits == [1.5]
    assert error.value.status == 429 and error.value.retry_after == "30"
    assert "operation=image_analysis" in caplog.text and "max_attempts=2" in caplog.text
    assert "test-secret-key" not in caplog.text


def test_image_rate_limit_without_retry_after_uses_bounded_backoff(monkeypatch) -> None:
    calls, waits = [], []
    def request(*_args, **_kwargs):
        calls.append(1)
        raise _image_error(429)
    monkeypatch.setattr("app.ai.openrouter.urlopen", request)
    monkeypatch.setattr("app.ai.openrouter.time.sleep", waits.append)
    with pytest.raises(ProviderRateLimitError):
        provider().inspect_image(b"image", "image/png")
    assert len(calls) == 2 and waits == [0.25]


@pytest.mark.parametrize(("status", "kind"), [(401, "authentication"), (403, "authorization"), (400, "invalid_request"), (500, "provider_error")])
def test_image_http_failures_are_structured(monkeypatch, status, kind) -> None:
    monkeypatch.setattr("app.ai.openrouter.urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(_image_error(status)))
    with pytest.raises(ProviderRequestError) as error:
        provider().inspect_image(b"image", "image/png")
    assert error.value.status == status and error.value.kind == kind


def test_image_timeout_and_network_failure_are_distinguished(monkeypatch) -> None:
    for failure, kind in [(TimeoutError("timed out"), "timeout"), (URLError("offline"), "network_error")]:
        monkeypatch.setattr("app.ai.openrouter.urlopen", lambda *_args, failure=failure, **_kwargs: (_ for _ in ()).throw(failure))
        with pytest.raises(ProviderRequestError) as error:
            provider().inspect_image(b"image", "image/png")
        assert error.value.kind == kind


def test_image_malformed_response_is_a_parsing_error(monkeypatch) -> None:
    mock_response(monkeypatch, "not-json")
    with pytest.raises(ModelResponseError):
        provider().inspect_image(b"image", "image/png")
