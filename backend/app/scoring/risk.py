"""Explainable risk scoring for the URL and DNS analyzer outputs.

The score sums the existing phishing-indicator weights unchanged. fraudurl contributes
``min(20, round(max(0, (probability - 0.5) * 40)))`` points: its neutral-or-lower
probability adds no risk points, and a high probability adds at most 20. DNS records
themselves are not suspicious. Resolver failures contribute zero points and lower
confidence because they leave DNS evidence unavailable. The final score is capped at
100. Scores 1-14 are Low Risk, 15-34 Suspicious, and 35-100 High Risk. A zero score
is Inconclusive: it does not establish safety. Confirmed Malicious is reserved for
trusted external confirmation, which this milestone does not implement.

Confidence is a deterministic evidence-coverage estimate, not a calibrated
probability. It starts at 0.25, adds 0.08 per positive evidence item (up to 0.4),
adds 0.15 when fraudurl returns a result, and 0.05 when DNS resolves; unavailable
fraudurl subtracts 0.1 and DNS errors subtract 0.15. The final value is clamped to
0.1-0.95.
"""

from __future__ import annotations

from app.models.dns import DnsAnalysisResult
from app.models.phishing import PhishingAnalysisResult
from app.models.risk import RiskAssessment, RiskClassification, RiskEvidence
from app.models.url import UrlAnalysisResult

_PHISHING_AS_URL_STRUCTURE = {
    "excessive_subdomains",
    "embedded_username",
    "ip_hostname",
    "long_hostname",
    "misleading_hostname_structure",
    "punycode_hostname",
    "unusual_port",
}


class RiskScorer:
    """Combine existing analysis evidence without inferring safety from no findings."""

    def assess(
        self,
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult,
        phishing_analysis: PhishingAnalysisResult,
    ) -> RiskAssessment:
        evidence: list[RiskEvidence] = []
        limitations: list[str] = [
            "Automated analysis does not prove that a website is safe or legitimate.",
            "No threat-intelligence confirmation is included in this assessment.",
        ]
        if phishing_analysis.fraudurl.status != "ok":
            limitations.append("The fraudurl phishing signal was unavailable or skipped.")

        for indicator in phishing_analysis.indicators:
            source = (
                "url_analysis"
                if indicator.type in _PHISHING_AS_URL_STRUCTURE
                else "phishing_analysis"
            )
            evidence.append(
                RiskEvidence(
                    source=source,
                    indicator=indicator.type,
                    severity=indicator.severity,
                    weight=indicator.score_contribution,
                    description=indicator.description,
                    evidence=indicator.evidence,
                )
            )

        fraud_result = phishing_analysis.fraudurl.result
        probability_value = fraud_result.get("fraud_probability") if fraud_result else None
        if isinstance(probability_value, (int, float)) and not isinstance(probability_value, bool):
            # Only evidence above the detector's 0.5 neutral point adds risk weight.
            fraud_weight = min(20, max(0, round((float(probability_value) - 0.5) * 40)))
            evidence.append(
                RiskEvidence(
                    source="phishing_analysis",
                    indicator="fraudurl_probability",
                    severity="medium" if fraud_weight >= 10 else "low",
                    weight=fraud_weight,
                    description="fraudurl's URL-only model probability, treated as one signal.",
                    evidence=f"fraud_probability={float(probability_value):.3f}; "
                    f"verdict={fraud_result.get('fraud_verdict', 'unavailable')}",
                )
            )

        if not url_analysis.is_valid:
            evidence.append(
                RiskEvidence(
                    source="url_analysis",
                    indicator="invalid_url",
                    severity="info",
                    weight=0,
                    description="URL structure could not be analyzed.",
                    evidence=url_analysis.validation_error or "URL was marked invalid.",
                )
            )

        dns_has_errors = bool(dns_analysis.errors) or dns_analysis.status in {"error", "partial"}
        if dns_has_errors:
            error_summary = "; ".join(
                f"{item.record_type}: {item.error_type}" for item in dns_analysis.errors
            ) or dns_analysis.status
            evidence.append(
                RiskEvidence(
                    source="dns_analysis",
                    indicator="dns_lookup_incomplete",
                    severity="info",
                    weight=0,
                    description="DNS lookup failed or returned incomplete results; this is not treated as malicious evidence.",
                    evidence=error_summary,
                )
            )
            limitations.append("DNS lookups were incomplete, so DNS evidence may be missing.")

        score = min(100, sum(item.weight for item in evidence))
        classification = self._classify(score)
        confidence = self._confidence(evidence, dns_analysis, phishing_analysis, dns_has_errors)

        if classification in {RiskClassification.SUSPICIOUS, RiskClassification.HIGH_RISK}:
            precautions = [
                "Do not enter credentials or payment details unless you independently verify the site.",
                "Use a known official website or contact channel instead of following this link.",
            ]
        elif classification is RiskClassification.LOW_RISK:
            precautions = [
                "Treat this URL as unverified; review the listed evidence before interacting with it."
            ]
        else:
            precautions = [
                "Treat the URL as unverified; an inconclusive result does not establish that it is safe."
            ]

        return RiskAssessment(
            classification=classification,
            score=score,
            confidence=confidence,
            contributing_indicators=evidence,
            recommended_precautions=precautions,
            limitations=limitations,
        )

    @staticmethod
    def _classify(score: int) -> RiskClassification:
        if score == 0:
            return RiskClassification.INCONCLUSIVE
        if score < 15:
            return RiskClassification.LOW_RISK
        if score < 35:
            return RiskClassification.SUSPICIOUS
        return RiskClassification.HIGH_RISK

    @staticmethod
    def _confidence(
        evidence: list[RiskEvidence],
        dns_analysis: DnsAnalysisResult,
        phishing_analysis: PhishingAnalysisResult,
        dns_has_errors: bool,
    ) -> float:
        positive_count = sum(item.weight > 0 for item in evidence)
        confidence = 0.25 + min(0.4, positive_count * 0.08)
        if phishing_analysis.fraudurl.status == "ok":
            confidence += 0.15
        else:
            confidence -= 0.1
        if dns_analysis.resolution_succeeded:
            confidence += 0.05
        if dns_has_errors:
            confidence -= 0.15
        return round(min(0.95, max(0.1, confidence)), 2)
