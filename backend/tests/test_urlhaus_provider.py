from __future__ import annotations

import io
import json
from urllib.error import URLError

from app.threat_intel.base import ThreatIntelStatus
from app.threat_intel.urlhaus import UrlhausProvider

SAMPLE_URL = "https://example.com/path"


class FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeOpener:
    def __init__(self, payload: object | Exception):
        self.payload = payload
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if isinstance(self.payload, Exception):
            raise self.payload
        return FakeResponse(json.dumps(self.payload).encode())


def use_response(monkeypatch, payload: object | Exception) -> FakeOpener:
    opener = FakeOpener(payload)
    monkeypatch.setattr("app.threat_intel.urlhaus.build_opener", lambda *_: opener)
    return opener


def test_known_malicious_url_is_normalized(monkeypatch) -> None:
    opener = use_response(
        monkeypatch,
        {
            "query_status": "ok",
            "url": SAMPLE_URL,
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2026-01-02 03:04:05 UTC",
            "tags": ["test-tag"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
            "payloads": [{"urlhaus_download": "must not be exposed"}],
        },
    )

    result = UrlhausProvider(api_key="test-secret").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.MATCHED
    assert result.match_scope == "url"
    assert result.matched is True
    assert result.source == "URLhaus"
    assert result.indicator == SAMPLE_URL
    assert result.threat_type == "malware_download"
    assert result.confidence == 1
    assert result.evidence["url_status"] == "online"
    assert result.reference == "https://urlhaus.abuse.ch/url/123/"
    assert "payloads" not in result.evidence
    assert opener.request.full_url == "https://urlhaus-api.abuse.ch/v1/url/"
    assert opener.request.get_header("Auth-key") == "test-secret"
    assert opener.timeout == 4


def test_domain_lookup_uses_urlhaus_host_endpoint(monkeypatch) -> None:
    opener = use_response(
        monkeypatch,
        {
            "query_status": "ok",
            "host": "example.com",
            "urls": [
                {
                    "threat": "malware_download",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
                }
            ],
        },
    )

    result = UrlhausProvider(api_key="key").lookup("example.com")

    assert result.status is ThreatIntelStatus.MATCHED
    assert result.match_scope == "host"
    assert opener.request.full_url == "https://urlhaus-api.abuse.ch/v1/host/"
    assert opener.request.data == b"host=example.com"


def test_lookup_strips_credentials_and_fragment_before_sharing_url(monkeypatch) -> None:
    opener = use_response(monkeypatch, {"query_status": "no_results"})

    result = UrlhausProvider(api_key="key").lookup(
        "https://alice:secret@example.com/path?campaign=demo#private-fragment"
    )

    assert result.status is ThreatIntelStatus.NO_MATCH
    assert opener.request.data == b"url=https%3A%2F%2Fexample.com%2Fpath%3Fcampaign%3Ddemo"
    assert b"alice" not in opener.request.data
    assert b"secret" not in opener.request.data
    assert b"private-fragment" not in opener.request.data


def test_no_match_is_distinct_from_unavailable(monkeypatch) -> None:
    use_response(monkeypatch, {"query_status": "no_results"})

    result = UrlhausProvider(api_key="key").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.NO_MATCH
    assert result.matched is False
    assert result.error is None


def test_missing_key_reports_unavailable_without_request() -> None:
    result = UrlhausProvider(api_key="").lookup(
        "https://alice:secret@example.com/path#private-fragment"
    )

    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert result.matched is None
    assert result.indicator == "https://example.com/path"
    assert "not configured" in (result.error or "")


def test_timeout_is_unavailable(monkeypatch) -> None:
    use_response(monkeypatch, URLError(TimeoutError("timed out")))

    result = UrlhausProvider(api_key="key").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert result.matched is None
    assert "timed out" in (result.error or "")


def test_rate_limit_is_unavailable(monkeypatch) -> None:
    from urllib.error import HTTPError

    use_response(
        monkeypatch,
        HTTPError("https://urlhaus-api.abuse.ch/v1/url/", 429, "Too Many Requests", {}, None),
    )

    result = UrlhausProvider(api_key="key").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert "rate limited" in (result.error or "")


def test_malformed_response_is_unavailable(monkeypatch) -> None:
    use_response(monkeypatch, {"unexpected": "shape"})

    result = UrlhausProvider(api_key="key").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert result.matched is None


def test_invalid_provider_json_is_unavailable(monkeypatch) -> None:
    class InvalidJsonResponse(FakeResponse):
        pass

    response = InvalidJsonResponse(b"not json")
    opener = FakeOpener({})
    opener.open = lambda *_args, **_kwargs: response
    monkeypatch.setattr("app.threat_intel.urlhaus.build_opener", lambda *_: opener)

    result = UrlhausProvider(api_key="key").lookup(SAMPLE_URL)

    assert result.status is ThreatIntelStatus.UNAVAILABLE
    assert "invalid JSON" in (result.error or "")
