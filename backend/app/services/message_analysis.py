from app.ai.openrouter import OpenRouterProvider
from app.analyzers.message import MessageAnalyzer
from app.analyzers.message import normalize_message_text
from app.analyzers.phishing import PhishingAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.message import AIExplanation, MessageURLAssessment
from app.scoring.risk import RiskScorer
from app.threat_intel.urlhaus import UrlhausProvider


def analyze_message_content(
    message: str,
    *,
    message_analyzer: MessageAnalyzer,
    phishing_analyzer: PhishingAnalyzer,
    url_analyzer: UrlAnalyzer,
    threat_intel_provider: UrlhausProvider,
    ai_provider: OpenRouterProvider,
    risk_scorer: RiskScorer,
    ai_explanation: AIExplanation | None = None,
    reanalyze_semantics: bool = False,
) -> dict[str, object]:
    """Run the shared deterministic, URL reputation, AI, and risk pipeline."""
    message = normalize_message_text(message)
    analysis = message_analyzer.analyze(message)
    intel_results = []
    url_assessments: list[MessageURLAssessment] = []
    for extracted_url in analysis["extracted_urls"]:
        parsed = url_analyzer.analyze(extracted_url)
        phishing = phishing_analyzer.analyze(parsed)
        url_intel = []
        if parsed.is_valid and parsed.normalized_url and parsed.hostname:
            if parsed.has_query or parsed.has_username:
                url_intel.append(threat_intel_provider.lookup(parsed.hostname))
            else:
                exact = threat_intel_provider.lookup(parsed.normalized_url)
                url_intel.append(exact)
                if exact.status.value == "no_match":
                    url_intel.append(threat_intel_provider.lookup(parsed.hostname))
        intel_results.extend(url_intel)
        url_assessments.append(MessageURLAssessment(
            submitted_url=extracted_url,
            url_analysis=parsed,
            phishing_analysis=phishing,
            threat_intelligence=url_intel,
        ))

    indicator_payload = [item.model_dump(mode="json") for item in analysis["deterministic_indicators"]]
    intel_payload = [item.model_dump(mode="json") for item in intel_results]
    url_evidence_payload = [
        {
            "url": item.url_analysis.normalized_url or item.submitted_url,
            "hostname": item.url_analysis.hostname,
            "phishing_indicators": [
                indicator.model_dump(mode="json")
                for indicator in item.phishing_analysis.indicators
            ],
            "phishing_score": item.phishing_analysis.score,
            "threat_intelligence": [result.model_dump(mode="json") for result in item.threat_intelligence],
        }
        for item in url_assessments
    ]
    if ai_explanation is None or reanalyze_semantics:
        file_explanation = ai_explanation
        try:
            semantic_explanation = ai_provider.explain(
                message, indicator_payload, intel_payload, True, url_evidence_payload
            )
            if file_explanation is None or not reanalyze_semantics:
                ai_explanation = semantic_explanation
            else:
                ai_explanation = file_explanation.model_copy(update={
                    "suspicious_indicators": list(dict.fromkeys(
                        file_explanation.suspicious_indicators + semantic_explanation.suspicious_indicators
                    )),
                    "evidence": list(dict.fromkeys(file_explanation.evidence + semantic_explanation.evidence)),
                    "recommended_actions": list(dict.fromkeys(
                        file_explanation.recommended_actions + semantic_explanation.recommended_actions
                    )),
                    "limitations": list(dict.fromkeys(
                        file_explanation.limitations + semantic_explanation.limitations
                    )),
                    "confidence": semantic_explanation.confidence,
                    "scam_assessment": semantic_explanation.scam_assessment,
                })
        except Exception:
            if file_explanation is None:
                ai_explanation = AIExplanation(
                    status="unavailable",
                    limitations=["OpenRouter explanation failed; deterministic analysis is preserved."],
                )
            else:
                ai_explanation = file_explanation.model_copy(update={
                    "limitations": list(dict.fromkeys(
                        file_explanation.limitations + ["Semantic scam analysis failed; extracted text and other evidence are preserved."]
                    )),
                    "scam_assessment": None,
                })
    risk = risk_scorer.assess_message(
        analysis["deterministic_indicators"], intel_results, ai_explanation, url_assessments
    )
    limitations = list(risk.limitations)
    if analysis["extracted_urls"]:
        limitations.append(
            "Extracted URLs were checked against threat intelligence only; no website request or redirect following was performed."
        )
        if any(item.url_analysis.has_query or item.url_analysis.has_username for item in url_assessments):
            limitations.append(
                "URL queries and embedded credentials were not sent to threat intelligence; those URLs received hostname-only lookup."
            )
    else:
        limitations.append("No URLs were extracted; URL analysis contributed no evidence to the risk score.")
    limitations.append("When available, submitted content is sent to OpenRouter for advisory interpretation.")
    return {
        "analysis": analysis,
        "url_threat_intelligence": intel_results,
        "url_assessments": url_assessments,
        "risk_assessment": risk,
        "ai_explanation": ai_explanation,
        "limitations": list(dict.fromkeys(limitations)),
    }
