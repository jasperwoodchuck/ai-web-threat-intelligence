from __future__ import annotations

from typing import Any

from app.analyzers.phishing import FraudUrlAdapter, PhishingAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.phishing import FraudUrlSignal


class FakeFraudUrl:
    def __init__(self, result: FraudUrlSignal | None = None, error: Exception | None = None):
        self.result = result or FraudUrlSignal(
            status="ok",
            result={"fraud_verdict": "LEGITIMATE", "fraud_probability": 0.1},
            score_contribution=2,
        )
        self.error = error

    def analyze(self, url: str) -> FraudUrlSignal:
        if self.error:
            raise self.error
        return self.result


def analyze(url: str, *, detector: object | None = None):
    parsed = UrlAnalyzer().analyze(url)
    return PhishingAnalyzer(fraudurl_analyzer=detector or FakeFraudUrl()).analyze(parsed)


def indicator_types(result: Any) -> set[str]:
    return {indicator.type for indicator in result.indicators}


def test_benign_looking_url_has_no_obvious_heuristic_indicators() -> None:
    result = analyze("https://example.com/about")

    assert result.is_suspicious is False
    assert result.score < 25
    assert result.indicators == []


def test_unusually_long_url_is_reported() -> None:
    result = analyze(f"https://example.com/{'a' * 210}")

    assert "long_url" in indicator_types(result)


def test_excessive_subdomains_are_reported() -> None:
    result = analyze("https://one.two.three.four.example.com/")

    assert "excessive_subdomains" in indicator_types(result)


def test_ip_address_hostname_is_reported() -> None:
    result = analyze("http://192.0.2.10/login")

    assert "ip_hostname" in indicator_types(result)


def test_embedded_username_is_reported() -> None:
    result = analyze("https://account@example.com/")

    assert "embedded_username" in indicator_types(result)


def test_suspicious_encoding_is_reported() -> None:
    result = analyze("https://example.com/%2f%40%2e/login")

    assert "suspicious_encoding" in indicator_types(result)


def test_suspicious_keyword_is_reported() -> None:
    result = analyze("https://example.com/login/verify")

    assert "suspicious_keyword" in indicator_types(result)
    keyword = next(item for item in result.indicators if item.type == "suspicious_keyword")
    assert keyword.evidence == "login, verify"


def test_multiple_indicators_are_returned_together() -> None:
    result = analyze("https://user@192.0.2.10/login/verify")

    assert {"ip_hostname", "embedded_username", "suspicious_keyword"} <= indicator_types(result)
    assert result.score >= 25
    assert result.is_suspicious is True


def test_malformed_url_is_handled_without_running_fraudurl() -> None:
    result = analyze("https:///missing-host")

    assert result.is_suspicious is False
    assert result.score == 0
    assert result.indicators == []
    assert result.fraudurl.status == "skipped"


def test_fraudurl_result_is_preserved_as_an_independent_signal() -> None:
    raw = {"fraud_verdict": "FRAUD", "fraud_probability": 0.9, "top_reasons": ["reason"]}
    result = analyze(
        "https://example.com/",
        detector=FakeFraudUrl(
            FraudUrlSignal(status="ok", result=raw, score_contribution=27)
        ),
    )

    assert result.fraudurl.result == raw
    assert result.fraudurl.score_contribution == 27
    assert result.score == 27
    assert result.is_suspicious is True


def test_fraudurl_failure_does_not_fail_analysis() -> None:
    result = analyze("https://example.com/", detector=FakeFraudUrl(error=RuntimeError("failed")))

    assert result.fraudurl.status == "error"
    assert result.fraudurl.error == "RuntimeError: failed"
    assert result.is_suspicious is False


def test_fraudurl_adapter_preserves_library_json(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = '{"fraud_verdict":"REVIEW","fraud_probability":0.5,"top_reasons":[]}'
        stderr = ""

    def fake_run(command, **kwargs):
        assert command[-3:] == ["--url", "https://example.com/", "--quiet"]
        assert kwargs["timeout"] > 0
        return Completed()

    monkeypatch.setattr("app.analyzers.phishing.subprocess.run", fake_run)
    result = FraudUrlAdapter().analyze("https://example.com/")

    assert result.status == "ok"
    assert result.result == {
        "fraud_verdict": "REVIEW",
        "fraud_probability": 0.5,
        "top_reasons": [],
    }
    assert result.score_contribution == 15
