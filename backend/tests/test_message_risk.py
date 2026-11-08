from datetime import UTC, datetime

from app.models.message import AIExplanation, MessageIndicator, MessageURLAssessment, ScamAssessment, ScamSignal
from app.models.phishing import FraudUrlSignal, PhishingAnalysisResult, PhishingIndicator
from app.scoring.risk import RiskScorer
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus
from app.models.url import UrlAnalysisResult


def result(status, scope=None):
    return ThreatIntelResult(status=status, matched=status is ThreatIntelStatus.MATCHED, source="URLhaus", indicator="https://example.test/", match_scope=scope, confidence=1.0 if scope else None, checked_at=datetime.now(UTC))


def test_suspicious_language_and_ai_never_confirm_malicious() -> None:
    indicator = MessageIndicator(category="urgency", severity="high", description="Pressure", evidence="act now")
    ai = AIExplanation(status="available", summary="Definitely malicious", confidence=1)
    assessment = RiskScorer().assess_message([indicator], [], ai)
    assert assessment.classification.value != "Confirmed Malicious"


def test_exact_urlhaus_match_confirms_and_no_match_does_not_prove_safety() -> None:
    exact = RiskScorer().assess_message([], [result(ThreatIntelStatus.MATCHED, "url")], AIExplanation(status="unavailable"))
    assert exact.classification.value == "Confirmed Malicious"
    no_match = RiskScorer().assess_message([], [result(ThreatIntelStatus.NO_MATCH)], AIExplanation(status="unavailable"))
    assert no_match.classification.value == "Low Risk"
    assert "not proof" in " ".join(no_match.limitations)


def test_unavailable_provider_reduces_confidence_and_records_limitation() -> None:
    unavailable = result(ThreatIntelStatus.UNAVAILABLE)
    assessment = RiskScorer().assess_message([], [unavailable], AIExplanation(status="unavailable"))
    assert assessment.confidence < 0.85
    assert any("unavailable" in item for item in assessment.limitations)


def semantic(score: int, classification: str, *, scam: bool = False, reasoning: str = "Contextual reading.") -> AIExplanation:
    return AIExplanation(
        status="available",
        summary=reasoning,
        confidence=0.88,
        scam_assessment=ScamAssessment(
            classification=classification,
            risk_score=score,
            confidence=0.88,
            has_scam_intent=scam,
            impersonates_entity=False,
            requests_money=False,
            requests_credentials=False,
            uses_urgency=False,
            has_suspicious_instructions=False,
            has_url=False,
            claims_transaction=False,
            signals=[],
            reasoning=reasoning,
        ),
    )


def url_assessment(url: str, indicators: list[PhishingIndicator]) -> MessageURLAssessment:
    parsed = UrlAnalysisResult(
        original_url=url, normalized_url=url, scheme="https", hostname="example.test",
        path="/", registered_domain="example.test", public_suffix="test", is_valid=True,
    )
    return MessageURLAssessment(
        submitted_url=url,
        url_analysis=parsed,
        phishing_analysis=PhishingAnalysisResult(
            is_suspicious=bool(indicators), score=sum(item.score_contribution for item in indicators),
            indicators=indicators, fraudurl=FraudUrlSignal(status="skipped"),
        ),
        threat_intelligence=[],
    )


def test_generic_financial_safety_advice_is_not_high_risk() -> None:
    advice = "this is to remind you that do not pay ppl online without knowing"
    indicators = [MessageIndicator(category="payment_request", severity="high", description="payment word", evidence=advice)]
    assessment = RiskScorer().assess_message(indicators, [], semantic(8, "low", reasoning="This warns against paying unknown people."))
    assert assessment.score == 8
    assert assessment.classification.value == "Low Risk"
    assert not any(item.source.startswith("url_") for item in assessment.contributing_indicators)


def test_generic_payment_word_and_legitimate_notice_are_not_high_risk() -> None:
    indicator = MessageIndicator(category="payment_request", severity="high", description="payment word", evidence="Your payment receipt is available in your monthly statement.")
    for explanation in (semantic(6, "low"), semantic(12, "low")):
        assessment = RiskScorer().assess_message([indicator], [], explanation)
        assert assessment.classification.value != "High Risk"


def test_ambiguous_semantic_message_remains_suspicious() -> None:
    assessment = RiskScorer().assess_message([], [], semantic(42, "suspicious", reasoning="The request is unclear and asks the recipient to contact an unknown sender."))
    assert assessment.classification.value == "Suspicious"


def test_url_evidence_is_separate_and_can_raise_phishing_message_to_high() -> None:
    suspicious = PhishingIndicator(
        type="typosquatting_domain", severity="high", description="Brand-lookalike domain",
        evidence="paypa1.example.test resembles PayPal", score_contribution=30,
    )
    assessment = RiskScorer().assess_message(
        [], [], semantic(45, "suspicious", scam=True),
        [url_assessment("https://paypa1.example.test/login", [suspicious])],
    )
    assert assessment.classification.value == "High Risk"
    assert any(item.source == "url_phishing_analysis" for item in assessment.contributing_indicators)


def test_phishing_and_package_delivery_scenarios_reach_high_risk_with_suspicious_urls() -> None:
    scenarios = [
        ("Your bank account is suspended. Verify now at https://secure-example.test/login", "brand_impersonation_domain"),
        ("Your package could not be delivered. Confirm your address at https://delivery-example.test/reschedule", "misleading_hostname_structure"),
    ]
    for message, signal_type in scenarios:
        signal = PhishingIndicator(
            type=signal_type, severity="high", description="Suspicious URL structure",
            evidence=f"URL used in message: {message.split()[-1]}", score_contribution=25,
        )
        assessment = RiskScorer().assess_message(
            [], [], semantic(55, "suspicious", scam=True),
            [url_assessment(message.split()[-1], [signal])],
        )
        assert assessment.classification.value == "High Risk"


def test_legitimate_looking_url_is_not_automatically_safe_or_malicious() -> None:
    assessment = RiskScorer().assess_message(
        [], [], semantic(35, "suspicious"), [url_assessment("https://example.test/", [])]
    )
    assert assessment.classification.value == "Suspicious"
    assert not any(item.source == "url_phishing_analysis" and item.weight > 0 for item in assessment.contributing_indicators)
    assert any("not proof" in item for item in assessment.limitations)
