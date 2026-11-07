from __future__ import annotations

from typing import Any

from app.analyzers.phishing import FraudUrlAdapter, PhishingAnalyzer
from app.analyzers.typosquatting import detect_lookalike_domain
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


def test_yovtube_identifies_youtube_as_possible_intended_site() -> None:
    result = analyze("https://yovtube.com")

    indicator = next(item for item in result.indicators if item.type == "typosquatting_domain")
    assert result.typosquatting.detected is True
    assert result.typosquatting.submitted_domain == "yovtube.com"
    assert result.typosquatting.possible_intended_site == "youtube.com"
    assert result.typosquatting.similarity == 0.86
    assert result.typosquatting.edit_distance == 1
    assert "youtube.com" in indicator.description
    assert "similarity=0.86 (high)" in indicator.evidence
    assert "edit_distance=1" in indicator.evidence


def test_missing_character_lookalikes_are_detected() -> None:
    for domain in ("youtub.com", "yotube.com"):
        result = analyze(f"https://{domain}")
        indicator = next(item for item in result.indicators if item.type == "typosquatting_domain")
        assert "youtube.com" in indicator.description


def test_legitimate_known_domains_and_www_subdomain_are_not_flagged() -> None:
    for url in (
        "https://www.youtube.com/",
        "https://youtube.com/",
        "https://www.google.com/",
        "https://example.org/",
        "https://google.co.uk/",
    ):
        result = analyze(url)
        assert "typosquatting_domain" not in indicator_types(result)
        assert result.typosquatting.detected is False
        assert result.typosquatting.possible_intended_site is None


def test_www_subdomain_is_stripped_before_lookalike_check() -> None:
    result = analyze("https://www.yovtube.com/account")

    indicator = next(item for item in result.indicators if item.type == "typosquatting_domain")
    assert "registered_domain=yovtube.com" in indicator.evidence
    assert "possible_intended_site=youtube.com" in indicator.evidence
    assert result.typosquatting.submitted_domain == "yovtube.com"
    assert result.typosquatting.possible_intended_site == "youtube.com"


def test_lookalike_domain_normalizes_case() -> None:
    result = analyze("https://YOVTUBE.COM/")

    indicator = next(item for item in result.indicators if item.type == "typosquatting_domain")
    assert "youtube.com" in indicator.description
    assert "registered_domain=yovtube.com" in indicator.evidence


def test_edit_distance_covers_transposition_and_obvious_confusables() -> None:
    transposed = analyze("https://youtbue.com/")
    confusable = analyze("https://g00gle.com/")

    assert "youtube.com" in next(
        item.description for item in transposed.indicators if item.type == "typosquatting_domain"
    )
    assert "google.com" in next(
        item.description for item in confusable.indicators if item.type == "typosquatting_domain"
    )


def test_edit_distance_covers_repeated_character() -> None:
    result = analyze("https://youttube.com/")

    indicator = next(item for item in result.indicators if item.type == "typosquatting_domain")
    assert "youtube.com" in indicator.description
    assert "edit_distance=1" in indicator.evidence


def test_multiple_candidates_choose_best_then_stable_lexical_match() -> None:
    match = detect_lookalike_domain("abcdg.com", ("abcde.com", "abcdf.com"))

    assert match is not None
    assert match.intended_domain == "abcde.com"


def test_unrelated_domain_does_not_match_curated_sites() -> None:
    assert detect_lookalike_domain("example.com") is None
    assert detect_lookalike_domain("youtube.co.uk") is None
    result = analyze("https://example.com")
    assert result.typosquatting.detected is False
    assert result.typosquatting.possible_intended_site is None


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
