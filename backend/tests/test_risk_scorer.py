from __future__ import annotations

from app.models.dns import DnsAnalysisResult, DnsLookupError
from app.models.phishing import (
    FraudUrlSignal,
    PhishingAnalysisResult,
    PhishingIndicator,
)
from app.models.risk import RiskClassification
from app.models.url import UrlAnalysisResult
from app.scoring.risk import RiskScorer


def make_url() -> UrlAnalysisResult:
    return UrlAnalysisResult(
        original_url="https://example.com/",
        normalized_url="https://example.com/",
        scheme="https",
        hostname="example.com",
        path="/",
        registered_domain="example.com",
        public_suffix="com",
        is_valid=True,
    )


def make_dns(*, failed: bool = False) -> DnsAnalysisResult:
    errors = (
        [DnsLookupError(record_type="A", error_type="Timeout", message="timed out")]
        if failed
        else []
    )
    return DnsAnalysisResult(
        hostname="example.com",
        status="error" if failed else "ok",
        resolution_succeeded=not failed,
        errors=errors,
    )


def make_phishing(
    indicators: list[PhishingIndicator] | None = None,
    *,
    fraud_probability: float | None = 0.5,
) -> PhishingAnalysisResult:
    result = (
        {"fraud_probability": fraud_probability, "fraud_verdict": "REVIEW"}
        if fraud_probability is not None
        else None
    )
    return PhishingAnalysisResult(
        is_suspicious=bool(indicators),
        score=min(100, sum(item.score_contribution for item in indicators or [])),
        indicators=indicators or [],
        fraudurl=FraudUrlSignal(status="ok" if result else "error", result=result),
    )


def make_indicator(
    indicator: str,
    weight: int,
    *,
    severity: str = "low",
) -> PhishingIndicator:
    return PhishingIndicator(
        type=indicator,
        severity=severity,
        score_contribution=weight,
        description=f"Description of {indicator}",
        evidence=f"Evidence for {indicator}",
    )


def test_no_meaningful_indicators_is_inconclusive_not_safe() -> None:
    assessment = RiskScorer().assess(make_url(), make_dns(), make_phishing(fraud_probability=0.2))

    assert assessment.classification is RiskClassification.INCONCLUSIVE
    assert assessment.score == 0
    assert any("does not prove" in limitation for limitation in assessment.limitations)


def test_one_low_severity_indicator_produces_low_risk() -> None:
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing([make_indicator("long_url", 10)], fraud_probability=None)
    )

    assert assessment.classification is RiskClassification.LOW_RISK
    assert assessment.score == 10


def test_multiple_suspicious_indicators_produce_suspicious_classification() -> None:
    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(
            [make_indicator("suspicious_keyword", 12), make_indicator("long_url", 10)],
            fraud_probability=0.6,
        ),
    )

    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert assessment.score == 26


def test_strong_phishing_evidence_produces_high_risk() -> None:
    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(
            [
                make_indicator("ip_hostname", 20, severity="high"),
                make_indicator("embedded_username", 20, severity="high"),
            ],
            fraud_probability=0.9,
        ),
    )

    assert assessment.classification is RiskClassification.HIGH_RISK
    assert assessment.score == 56


def test_heuristics_alone_never_produce_confirmed_malicious() -> None:
    indicators = [make_indicator(f"heuristic_{index}", 20, severity="high") for index in range(8)]
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(indicators, fraud_probability=0.99)
    )

    assert assessment.score == 100
    assert assessment.classification is RiskClassification.HIGH_RISK
    assert assessment.classification is not RiskClassification.CONFIRMED_MALICIOUS


def test_original_indicator_evidence_and_source_are_preserved() -> None:
    original = make_indicator("ip_hostname", 20, severity="high")
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing([original], fraud_probability=None)
    )

    item = assessment.contributing_indicators[0]
    assert item.source == "url_analysis"
    assert item.indicator == original.type
    assert item.severity == original.severity
    assert item.weight == original.score_contribution
    assert item.description == original.description
    assert item.evidence == original.evidence


def test_confidence_is_bounded_when_dns_evidence_is_unavailable() -> None:
    assessment = RiskScorer().assess(
        make_url(), make_dns(failed=True), make_phishing(fraud_probability=None)
    )

    assert 0 <= assessment.confidence <= 1
    assert any(item.indicator == "dns_lookup_incomplete" for item in assessment.contributing_indicators)
    assert assessment.contributing_indicators[-1].weight == 0


def test_score_is_capped_at_documented_maximum() -> None:
    indicators = [make_indicator(f"heuristic_{index}", 20) for index in range(8)]
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(indicators, fraud_probability=0.99)
    )

    assert assessment.score == 100
    assert assessment.score <= 100
