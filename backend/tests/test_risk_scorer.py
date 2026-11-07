from __future__ import annotations

from app.models.dns import DnsAnalysisResult, DnsLookupError
from app.models.phishing import (
    FraudUrlSignal,
    PhishingAnalysisResult,
    PhishingIndicator,
)
from app.models.risk import RiskClassification
from app.models.tls import TlsAnalysisResult, TlsCertificate, TlsFinding
from app.models.url import UrlAnalysisResult
from app.scoring.risk import RiskScorer
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus


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


def test_urlhaus_match_confirms_malicious_and_preserves_source_evidence() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.MATCHED,
        matched=True,
        source="URLhaus",
        indicator="https://example.com/path",
        match_scope="url",
        threat_type="malware_download",
        confidence=1,
        evidence={"url_status": "online"},
        reference="https://urlhaus.abuse.ch/url/123/",
    )

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.5), threat_intelligence=intel
    )

    assert assessment.classification is RiskClassification.CONFIRMED_MALICIOUS
    assert assessment.score == 100
    assert assessment.contributing_indicators[-1].source == "URLhaus"
    assert assessment.contributing_indicators[-1].evidence.find("malware_download") >= 0


def test_no_urlhaus_match_does_not_mean_low_risk() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.NO_MATCH,
        matched=False,
        source="URLhaus",
        indicator="https://example.com/",
    )

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.2), threat_intelligence=intel
    )

    assert assessment.classification is RiskClassification.INCONCLUSIVE
    assert assessment.score == 0
    assert any("does not establish" in text for text in assessment.limitations)


def test_unavailable_threat_intelligence_cannot_confirm_malicious() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.UNAVAILABLE,
        matched=None,
        source="URLhaus",
        indicator="https://example.com/",
        error="provider timeout",
    )

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.2), threat_intelligence=intel
    )

    assert assessment.classification is not RiskClassification.CONFIRMED_MALICIOUS
    assert any("timeout" in text for text in assessment.limitations)

    no_match = ThreatIntelResult(
        status=ThreatIntelStatus.NO_MATCH,
        matched=False,
        source="URLhaus",
        indicator="https://example.com/",
    )
    checked_assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.2), threat_intelligence=no_match
    )
    assert assessment.confidence < checked_assessment.confidence


def test_host_association_is_not_an_exact_url_confirmation() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.MATCHED,
        matched=True,
        source="URLhaus",
        indicator="example.com",
        match_scope="host",
        threat_type="malware_download",
        confidence=1,
    )

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.2), threat_intelligence=intel
    )

    assert assessment.classification is RiskClassification.HIGH_RISK
    assert assessment.classification is not RiskClassification.CONFIRMED_MALICIOUS
    assert assessment.contributing_indicators[-1].indicator == "known_malicious_host"


def test_valid_tls_does_not_reduce_or_improve_the_risk_score() -> None:
    scorer = RiskScorer()
    url = make_url()
    dns = make_dns()
    phishing = make_phishing([make_indicator("suspicious_keyword", 12)])
    baseline = scorer.assess(url, dns, phishing)
    valid_tls = TlsAnalysisResult(
        status="ok",
        supported=True,
        connection_successful=True,
        hostname="example.com",
        port=443,
        protocol_version="TLSv1.3",
        certificate_verified=True,
        certificate=TlsCertificate(hostname_matches=True),
        certificate_chain=[],
        findings=[],
    )

    with_tls = scorer.assess(url, dns, phishing, valid_tls)

    assert with_tls.score == baseline.score
    assert with_tls.classification is baseline.classification


def test_expired_tls_certificate_adds_security_evidence() -> None:
    tls = TlsAnalysisResult(
        status="error",
        supported=True,
        connection_successful=False,
        hostname="example.com",
        port=443,
        findings=[
            TlsFinding(
                type="certificate_expired",
                severity="high",
                description="The certificate has expired.",
                evidence="not_after was in the past",
            )
        ],
    )

    assessment = RiskScorer().assess(make_url(), make_dns(), make_phishing(fraud_probability=None), tls)

    assert assessment.score == 25
    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert assessment.contributing_indicators[-1].source == "tls_analysis"


def test_failed_supported_tls_check_reduces_confidence_not_safety_score() -> None:
    scorer = RiskScorer()
    url = make_url()
    dns = make_dns()
    phishing = make_phishing(fraud_probability=0.5)
    baseline = scorer.assess(url, dns, phishing)
    tls_failure = TlsAnalysisResult(
        status="error",
        supported=True,
        connection_successful=False,
        hostname="example.com",
        port=443,
    )

    with_tls_failure = scorer.assess(url, dns, phishing, tls_failure)

    assert with_tls_failure.score == baseline.score
    assert with_tls_failure.confidence == baseline.confidence - 0.1
