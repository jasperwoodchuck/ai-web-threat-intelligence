from __future__ import annotations

from io import BytesIO

import pytest

from app.analyzers.http import (
    HttpAnalyzer,
    _BoundedHeaderReader,
    _HeaderSizeLimitExceeded,
)
from app.analyzers.url import UrlAnalyzer
from app.models.dns import DnsAnalysisResult


def analyzed_url(value: str):
    return UrlAnalyzer().analyze(value)


def analyzed_dns(hostname: str, *addresses: str) -> DnsAnalysisResult:
    return DnsAnalysisResult(
        hostname=hostname,
        status="ok",
        resolution_succeeded=True,
        ipv4_addresses=list(addresses),
    )


class FakeResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]]) -> None:
        self.status = status
        self._headers = headers

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers

    def read(self, *_args, **_kwargs):
        raise AssertionError("The analyzer must not read response bodies.")


class FakeConnection:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False

    def request(self, method: str, target: str, headers: dict[str, str]) -> None:
        self.requests.append((method, target, headers))
        if self.error:
            raise self.error

    def getresponse(self) -> FakeResponse:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


def factory_for(connection: FakeConnection, captured: dict[str, object] | None = None):
    def factory(**kwargs):
        if captured is not None:
            captured.update(kwargs)
        return connection

    return factory


def test_successful_https_response_records_security_headers_without_body() -> None:
    connection = FakeConnection(
        FakeResponse(
            200,
            [
                ("Content-Security-Policy", "default-src 'self'"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Type", "text/html"),
            ],
        )
    )
    captured: dict[str, object] = {}
    url = analyzed_url("https://user:secret@example.test/private?token=abc#fragment")

    result = HttpAnalyzer(connection_factory=factory_for(connection, captured)).analyze(
        url, analyzed_dns("example.test", "8.8.8.8")
    )

    assert result.status == "ok"
    assert result.request_successful is True
    assert result.status_code == 200
    assert result.security_headers["content-security-policy"] == "default-src 'self'"
    assert result.security_headers["strict-transport-security"] == "max-age=31536000"
    assert result.security_headers["content-type"] == "text/html"
    assert result.findings == []
    assert connection.requests[0][0:2] == ("HEAD", "/private?token=abc")
    assert connection.requests[0][2]["Host"] == "example.test"
    assert "Authorization" not in connection.requests[0][2]
    assert captured == {
        "scheme": "https",
        "hostname": "example.test",
        "port": 443,
        "address": "8.8.8.8",
        "timeout": 4.0,
    }
    assert connection.closed is True


def test_redirect_is_recorded_but_not_followed_and_location_is_sanitized() -> None:
    connection = FakeConnection(
        FakeResponse(
            302,
            [("Location", "https://user:secret@other.example/path?token=private#fragment")],
        )
    )

    result = HttpAnalyzer(connection_factory=factory_for(connection)).analyze(
        analyzed_url("https://example.test/start"),
        analyzed_dns("example.test", "8.8.8.8"),
    )

    assert result.redirect_detected is True
    assert result.redirect_status_code == 302
    assert result.redirect_location == "https://other.example/path"
    assert result.security_headers["location"] == "https://other.example/path"
    assert "private" not in str(result.security_headers["location"])
    assert result.final_behavior == "redirect_not_followed"
    assert len(connection.requests) == 1
    assert any(item.type == "cross_origin_redirect" for item in result.findings)


def test_https_to_http_redirect_is_a_finding() -> None:
    connection = FakeConnection(FakeResponse(301, [("Location", "http://example.test/login")]))

    result = HttpAnalyzer(connection_factory=factory_for(connection)).analyze(
        analyzed_url("https://example.test/"),
        analyzed_dns("example.test", "8.8.8.8"),
    )

    assert any(item.type == "https_downgrade_redirect" for item in result.findings)


def test_http_url_is_marked_insecure_without_hsts_expectation() -> None:
    connection = FakeConnection(FakeResponse(200, []))

    result = HttpAnalyzer(connection_factory=factory_for(connection)).analyze(
        analyzed_url("http://example.test/"),
        analyzed_dns("example.test", "8.8.8.8"),
    )
    finding_types = {item.type for item in result.findings}

    assert result.scheme == "http"
    assert result.port == 80
    assert "insecure_http" in finding_types
    assert "missing_hsts" not in finding_types


def test_timeout_is_reported_without_raising() -> None:
    connection = FakeConnection(error=TimeoutError())

    result = HttpAnalyzer(connection_factory=factory_for(connection)).analyze(
        analyzed_url("http://example.test/"),
        analyzed_dns("example.test", "8.8.8.8"),
    )

    assert result.status == "error"
    assert result.request_successful is False
    assert result.error == "HTTP response timed out."
    assert result.findings[0].type == "http_timeout"


def test_connection_failure_is_reported_without_raising() -> None:
    connection = FakeConnection(error=ConnectionRefusedError())

    result = HttpAnalyzer(connection_factory=factory_for(connection)).analyze(
        analyzed_url("http://example.test/"),
        analyzed_dns("example.test", "8.8.8.8"),
    )

    assert result.status == "error"
    assert result.request_successful is False
    assert result.findings[0].type == "http_request_failed"


def test_non_public_dns_destination_is_blocked_before_connecting() -> None:
    called = False

    def factory(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("Non-public destinations must not be contacted.")

    result = HttpAnalyzer(connection_factory=factory).analyze(
        analyzed_url("http://example.test/"),
        analyzed_dns("example.test", "8.8.8.8", "127.0.0.1"),
    )

    assert called is False
    assert result.status == "error"
    assert result.findings[0].type == "destination_not_public"


def test_response_header_reader_enforces_total_size_limit() -> None:
    reader = _BoundedHeaderReader(BytesIO(b"header data\r\n"), limit=5)

    with pytest.raises(_HeaderSizeLimitExceeded):
        reader.readline()
