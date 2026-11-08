from datetime import UTC, datetime

from app.models.message import AIExplanation, MessageIndicator
from app.scoring.risk import RiskScorer
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus


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
