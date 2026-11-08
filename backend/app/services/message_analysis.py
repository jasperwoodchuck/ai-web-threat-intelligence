from app.ai.openrouter import OpenRouterProvider
from app.analyzers.message import MessageAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.message import AIExplanation
from app.scoring.risk import RiskScorer
from app.threat_intel.urlhaus import UrlhausProvider


def analyze_message_content(
    message: str,
    *,
    message_analyzer: MessageAnalyzer,
    url_analyzer: UrlAnalyzer,
    threat_intel_provider: UrlhausProvider,
    ai_provider: OpenRouterProvider,
    risk_scorer: RiskScorer,
    ai_explanation: AIExplanation | None = None,
) -> dict[str, object]:
    """Run the shared deterministic, URL reputation, AI, and risk pipeline."""
    analysis = message_analyzer.analyze(message)
    intel_results = []
    for extracted_url in analysis["extracted_urls"]:
        parsed = url_analyzer.analyze(extracted_url)
        if not parsed.is_valid or not parsed.normalized_url or not parsed.hostname:
            continue
        if parsed.has_query or parsed.has_username:
            intel_results.append(threat_intel_provider.lookup(parsed.hostname))
            continue
        exact = threat_intel_provider.lookup(parsed.normalized_url)
        intel_results.append(exact)
        if exact.status.value == "no_match":
            intel_results.append(threat_intel_provider.lookup(parsed.hostname))

    indicator_payload = [item.model_dump(mode="json") for item in analysis["deterministic_indicators"]]
    intel_payload = [item.model_dump(mode="json") for item in intel_results]
    if ai_explanation is None:
        try:
            ai_explanation = ai_provider.explain(message, indicator_payload, intel_payload)
        except Exception:
            ai_explanation = AIExplanation(
                status="unavailable",
                limitations=["OpenRouter explanation failed; deterministic analysis is preserved."],
            )
    risk = risk_scorer.assess_message(
        analysis["deterministic_indicators"], intel_results, ai_explanation
    )
    limitations = list(risk.limitations)
    if analysis["extracted_urls"]:
        limitations.append(
            "Extracted URLs were checked against threat intelligence only; no website request or redirect following was performed."
        )
        if any(
            (parsed := url_analyzer.analyze(url)).has_query or parsed.has_username
            for url in analysis["extracted_urls"]
        ):
            limitations.append(
                "URL queries and embedded credentials were not sent to threat intelligence; those URLs received hostname-only lookup."
            )
    else:
        limitations.append("No HTTP/HTTPS URLs were extracted for threat-intelligence lookup.")
    limitations.append("When available, submitted content is sent to OpenRouter for advisory interpretation.")
    return {
        "analysis": analysis,
        "url_threat_intelligence": intel_results,
        "risk_assessment": risk,
        "ai_explanation": ai_explanation,
        "limitations": list(dict.fromkeys(limitations)),
    }
