from __future__ import annotations

from app.models.dns import DnsAnalysisResult, DnsLookupError
from app.models.http import HttpAnalysisResult, HttpFinding
from app.models.phishing import (
    FraudUrlSignal,
    PhishingAnalysisResult,
    PhishingIndicator,
)
from app.models.risk import RiskClassification
from app.models.tls import TlsAnalysisResult, TlsCertificate, TlsFinding
from app.models.url import UrlAnalysisResult
from app.analyzers.url import UrlAnalyzer
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


def assert_score_matches_impacts(assessment) -> None:
    assert sum(item.weight for item in assessment.contributing_indicators) == assessment.score


def test_no_meaningful_indicators_is_low_risk_but_not_proven_safe() -> None:
    assessment = RiskScorer().assess(make_url(), make_dns(), make_phishing(fraud_probability=0.2))

    assert assessment.classification is RiskClassification.LOW_RISK
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
    assert assessment.score == 24


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
    assert assessment.score == 46


def test_heuristics_alone_never_produce_confirmed_malicious() -> None:
    indicators = [make_indicator(f"heuristic_{index}", 20, severity="high") for index in range(8)]
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(indicators, fraud_probability=0.99)
    )

    assert assessment.score == 86
    assert assessment.classification is RiskClassification.HIGH_RISK
    assert assessment.classification is not RiskClassification.CONFIRMED_MALICIOUS


def test_original_indicator_evidence_and_source_are_preserved() -> None:
    original = make_indicator("ip_hostname", 20, severity="high")
    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing([original], fraud_probability=None)
    )

    item = next(
        item
        for item in assessment.contributing_indicators
        if item.indicator == original.type
    )
    assert item.source == "url_analysis"
    assert item.indicator == original.type
    assert item.severity == original.severity
    assert item.weight > 0
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

    assert assessment.score == 86
    assert assessment.score <= 100
    assert_score_matches_impacts(assessment)


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
    assert assessment.score == 80
    threat_evidence = next(
        item for item in assessment.contributing_indicators if item.source == "URLhaus"
    )
    assert "malware_download" in threat_evidence.evidence
    assert_score_matches_impacts(assessment)


def test_no_urlhaus_match_scores_low_but_does_not_establish_safety() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.NO_MATCH,
        matched=False,
        source="URLhaus",
        indicator="https://example.com/",
    )

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(fraud_probability=0.2), threat_intelligence=intel
    )

    assert assessment.classification is RiskClassification.LOW_RISK
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
    assert any(
        item.source == "tls_analysis" and item.indicator == "certificate_expired"
        for item in assessment.contributing_indicators
    )


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
    assert with_tls_failure.confidence <= baseline.confidence


def test_http_security_findings_are_preserved_in_risk_assessment() -> None:
    http_analysis = HttpAnalysisResult(
        status="ok",
        supported=True,
        request_successful=True,
        scheme="http",
        hostname="example.com",
        port=80,
        status_code=200,
        findings=[
            HttpFinding(
                type="insecure_http",
                severity="medium",
                description="The URL uses unencrypted HTTP.",
                evidence="scheme=http",
                score_contribution=10,
            )
        ],
    )

    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(fraud_probability=None),
        http_analysis=http_analysis,
    )

    evidence = next(
        item
        for item in assessment.contributing_indicators
        if item.indicator == "insecure_http"
    )
    assert assessment.score == 10
    assert evidence.indicator == "insecure_http"
    assert evidence.weight == 10
    assert evidence.evidence == "scheme=http"


def test_http_failure_reduces_confidence_without_adding_risk_points() -> None:
    scorer = RiskScorer()
    phishing = make_phishing(fraud_probability=0.5)
    baseline = scorer.assess(make_url(), make_dns(), phishing)
    failed_http = HttpAnalysisResult(
        status="error",
        supported=True,
        request_successful=False,
        scheme="https",
        hostname="example.com",
        port=443,
        error="HTTP response timed out.",
    )

    assessment = scorer.assess(
        make_url(),
        make_dns(),
        phishing,
        http_analysis=failed_http,
    )

    assert assessment.score == baseline.score
    assert assessment.confidence <= baseline.confidence
    assert any(
        "response metadata could not be collected" in item
        for item in assessment.limitations
    )


def test_current_ui_example_url_is_low_risk_when_checks_find_no_suspicious_evidence() -> None:
    url = UrlAnalyzer().analyze("https://example.com")
    dns = DnsAnalysisResult(
        hostname="example.com",
        status="ok",
        resolution_succeeded=True,
        ipv4_addresses=["93.184.216.34"],
    )
    phishing = make_phishing(fraud_probability=0.1)
    tls = TlsAnalysisResult(
        status="ok",
        supported=True,
        connection_successful=True,
        hostname="example.com",
        port=443,
        protocol_version="TLSv1.3",
        certificate_verified=True,
        certificate=TlsCertificate(hostname_matches=True),
    )
    http = HttpAnalysisResult(
        status="ok",
        supported=True,
        request_successful=True,
        scheme="https",
        hostname="example.com",
        port=443,
        status_code=200,
        security_headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        },
    )
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.NO_MATCH,
        matched=False,
        source="URLhaus",
        indicator="https://example.com/",
    )

    assessment = RiskScorer().assess(url, dns, phishing, tls, intel, http)

    assert assessment.score == 0
    assert assessment.classification is RiskClassification.LOW_RISK
    assert assessment.confidence == 0.95
    assert_score_matches_impacts(assessment)
    assert {item.source for item in assessment.contributing_indicators} >= {
        "url_analysis",
        "dns_analysis",
        "phishing_analysis",
        "tls_analysis",
        "http_analysis",
        "URLhaus",
    }


def test_ip_and_unusual_port_combine_without_raw_score_summation() -> None:
    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(
            [
                make_indicator("ip_hostname", 20, severity="high"),
                make_indicator("unusual_port", 10),
            ],
            fraud_probability=None,
        ),
    )

    assert assessment.score == 28
    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert_score_matches_impacts(assessment)


def test_correlated_hostname_signals_are_discounted_and_duplicates_do_not_stack() -> None:
    duplicate_ip = make_indicator("ip_hostname", 20, severity="high")
    indicators = [
        duplicate_ip,
        duplicate_ip.model_copy(),
        make_indicator("long_hostname", 10),
    ]

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(indicators, fraud_probability=None)
    )

    assert assessment.score == 23
    assert [item.weight for item in assessment.contributing_indicators if item.indicator == "ip_hostname"] == [20, 0]
    assert_score_matches_impacts(assessment)


def test_phishing_indicators_combine_with_probability_weighted_fraudurl() -> None:
    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(
            [make_indicator("suspicious_keyword", 12)], fraud_probability=0.95
        ),
    )
    fraudurl_impact = next(
        item.weight
        for item in assessment.contributing_indicators
        if item.indicator == "fraudurl_probability"
    )

    assert assessment.score == 28
    assert fraudurl_impact == 16
    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert_score_matches_impacts(assessment)


def test_typosquatting_signal_contributes_once_to_url_risk() -> None:
    typosquat = make_indicator("typosquatting_domain", 30, severity="high").model_copy(
        update={"evidence": "registered_domain=yovtube.com; possible_intended_site=youtube.com"}
    )
    result = RiskScorer().assess(
        make_url(), make_dns(), make_phishing([typosquat], fraud_probability=None)
    )

    evidence = next(
        item for item in result.contributing_indicators if item.indicator == "typosquatting_domain"
    )
    assert evidence.source == "url_analysis"
    assert evidence.weight == 30
    assert result.score == 30
    assert result.classification is RiskClassification.SUSPICIOUS
    assert_score_matches_impacts(result)


def test_tls_problem_combines_with_suspicious_url_evidence() -> None:
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

    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing([make_indicator("suspicious_keyword", 12)], fraud_probability=None),
        tls,
    )

    assert assessment.score == 34
    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert_score_matches_impacts(assessment)


def test_http_findings_combine_with_suspicious_url_evidence() -> None:
    http = HttpAnalysisResult(
        status="ok",
        supported=True,
        request_successful=True,
        scheme="https",
        hostname="example.com",
        port=443,
        status_code=200,
        findings=[
            HttpFinding(
                type="missing_content_security_policy",
                severity="low",
                description="No CSP was found.",
                evidence="content-security-policy header is absent",
                score_contribution=2,
            )
        ],
    )

    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing([make_indicator("suspicious_keyword", 12)], fraud_probability=None),
        http_analysis=http,
    )

    assert assessment.score == 14
    assert assessment.classification is RiskClassification.LOW_RISK
    assert_score_matches_impacts(assessment)


def test_exact_urlhaus_match_combines_with_other_signals_without_overwriting_score() -> None:
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.MATCHED,
        matched=True,
        source="URLhaus",
        indicator="https://example.com/",
        match_scope="url",
        threat_type="malware_download",
        confidence=1,
    )

    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing(
            [make_indicator("ip_hostname", 20, severity="high")],
            fraud_probability=0.95,
        ),
        threat_intelligence=intel,
    )

    assert assessment.score == 87
    assert assessment.score < 100
    assert assessment.classification is RiskClassification.CONFIRMED_MALICIOUS
    assert_score_matches_impacts(assessment)


def test_multiple_weak_indicators_combine_to_suspicious() -> None:
    indicators = [
        make_indicator("weak_one", 12),
        make_indicator("weak_two", 12),
        make_indicator("weak_three", 12),
    ]

    assessment = RiskScorer().assess(
        make_url(), make_dns(), make_phishing(indicators, fraud_probability=None)
    )

    assert assessment.score == 32
    assert assessment.classification is RiskClassification.SUSPICIOUS
    assert_score_matches_impacts(assessment)


def test_errors_and_timeouts_add_uncertainty_not_risk_points() -> None:
    dns = make_dns(failed=True)
    tls = TlsAnalysisResult(
        status="error",
        supported=True,
        connection_successful=False,
        hostname="example.com",
        port=443,
    )
    http = HttpAnalysisResult(
        status="error",
        supported=True,
        request_successful=False,
        scheme="https",
        hostname="example.com",
        port=443,
        error="HTTP response timed out.",
    )
    intel = ThreatIntelResult(
        status=ThreatIntelStatus.UNAVAILABLE,
        matched=None,
        source="URLhaus",
        indicator="https://example.com/",
        error="provider timeout",
    )

    assessment = RiskScorer().assess(
        make_url(),
        dns,
        make_phishing(fraud_probability=None),
        tls,
        intel,
        http,
    )

    assert assessment.score == 0
    assert assessment.classification is RiskClassification.LOW_RISK
    assert all(item.weight == 0 for item in assessment.contributing_indicators)
    assert len(assessment.limitations) >= 4
    assert_score_matches_impacts(assessment)


def test_not_applicable_tls_has_no_evidence_or_penalty_for_http_url() -> None:
    url = UrlAnalyzer().analyze("http://example.com/")
    tls = TlsAnalysisResult(
        status="not_applicable",
        supported=False,
        connection_successful=False,
        hostname="example.com",
        port=80,
    )
    http = HttpAnalysisResult(
        status="ok",
        supported=True,
        request_successful=True,
        scheme="http",
        hostname="example.com",
        port=80,
        status_code=200,
        findings=[
            HttpFinding(
                type="insecure_http",
                severity="medium",
                description="The URL uses unencrypted HTTP.",
                evidence="scheme=http",
                score_contribution=10,
            )
        ],
    )
    assessment = RiskScorer().assess(
        url,
        make_dns(),
        make_phishing(fraud_probability=None),
        tls,
        http_analysis=http,
    )

    assert assessment.score == 10
    assert not any(item.source == "tls_analysis" for item in assessment.contributing_indicators)
    assert_score_matches_impacts(assessment)


def test_low_fraudurl_probability_is_limited_counterevidence() -> None:
    assessment = RiskScorer().assess(
        make_url(),
        make_dns(),
        make_phishing([make_indicator("suspicious_keyword", 15)], fraud_probability=0.1),
    )
    fraudurl = next(
        item for item in assessment.contributing_indicators if item.indicator == "fraudurl_probability"
    )

    assert assessment.score == 7
    assert fraudurl.weight == -8
    assert assessment.classification is RiskClassification.LOW_RISK
    assert_score_matches_impacts(assessment)
