"""Normalized, evidence-preserving risk aggregation.

Each signal is translated to a bounded risk strength, correlated observations receive
diminishing impact, and independent groups combine with noisy-OR. ``RiskEvidence.weight``
is the signed marginal change to the displayed 0-100 score; its sum therefore equals
the final score. Confidence measures analysis coverage and consistency, not risk.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.models.dns import DnsAnalysisResult
from app.models.http import HttpAnalysisResult
from app.models.phishing import PhishingAnalysisResult
from app.models.risk import RiskAssessment, RiskClassification, RiskEvidence
from app.models.tls import TlsAnalysisResult
from app.models.url import UrlAnalysisResult
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus

if TYPE_CHECKING:
    from app.models.message import AIExplanation, MessageIndicator

_URL_STRUCTURE_STRENGTHS = {
    "ip_hostname": 20,
    "embedded_username": 20,
    "unusual_port": 10,
    # IDN/punycode is descriptive evidence only unless a brand-lookalike match exists.
    "punycode_hostname": 0,
    "excessive_subdomains": 15,
    "misleading_hostname_structure": 15,
    "long_hostname": 10,
    "long_url": 10,
    "typosquatting_domain": 30,
    "brand_impersonation_domain": 15,
}
_TLS_RISK_STRENGTHS = {
    "certificate_expired": 25,
    "certificate_not_yet_valid": 20,
    "hostname_mismatch": 30,
    "weak_public_key": 18,
    "weak_signature_algorithm": 18,
    "obsolete_tls_version": 18,
    "certificate_verification_failed": 20,
    "certificate_expires_soon": 5,
}
_THREAT_EXACT_STRENGTH = 80
_THREAT_HOST_STRENGTH = 50
_CONFIRMED_SCORE_THRESHOLD = 70
_CORRELATION_FACTORS = (1.0, 0.35, 0.15, 0.05)


@dataclass(frozen=True)
class _RiskSignal:
    evidence: RiskEvidence
    strength: float = 0
    mitigation: int = 0
    correlation_group: str = ""
    order: int = 0


class RiskScorer:
    """Combine all applicable analyzer evidence without equating missing data to safety."""

    def assess(
        self,
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult,
        phishing_analysis: PhishingAnalysisResult,
        tls_analysis: TlsAnalysisResult | None = None,
        threat_intelligence: ThreatIntelResult | None = None,
        http_analysis: HttpAnalysisResult | None = None,
    ) -> RiskAssessment:
        signals: list[_RiskSignal] = []
        limitations = [
            "Automated analysis does not prove that a website is safe or legitimate.",
            "The normalized score is an evidence aggregation value, not a calibrated probability.",
        ]

        def add(
            source: str,
            indicator: str,
            severity: str,
            description: str,
            evidence: str,
            *,
            strength: float = 0,
            mitigation: int = 0,
            group: str = "",
            order: int,
        ) -> None:
            signals.append(
                _RiskSignal(
                    evidence=RiskEvidence(
                        source=source,
                        indicator=indicator,
                        severity=severity,
                        weight=0,
                        description=description,
                        evidence=evidence,
                    ),
                    strength=max(0.0, min(95.0, strength)),
                    mitigation=max(0, min(15, mitigation)),
                    correlation_group=group or f"{source}:{indicator}",
                    order=order,
                )
            )

        # URL syntax/structure is always considered. Parsing alone is not positive
        # evidence that a site is safe or malicious.
        if url_analysis.is_valid:
            add(
                "url_analysis",
                "url_structure_parsed",
                "info",
                "The submitted URL was syntactically parsed.",
                f"scheme={url_analysis.scheme}; hostname={url_analysis.hostname}; "
                f"registered_domain={url_analysis.registered_domain}; subdomain={url_analysis.subdomain}; "
                f"suffix={url_analysis.public_suffix}; port={url_analysis.port if url_analysis.port is not None else 'default'}; "
                f"path_present={bool(url_analysis.path)}; query={url_analysis.has_query}; "
                f"fragment={url_analysis.has_fragment}; username={url_analysis.has_username}; "
                f"password={url_analysis.has_password}; ip_hostname={url_analysis.is_ip_address}",
                order=0,
            )
        else:
            add(
                "url_analysis",
                "invalid_url",
                "info",
                "URL structure could not be analyzed.",
                url_analysis.validation_error or "URL was marked invalid.",
                order=0,
            )
            limitations.append("URL structure validation failed; downstream evidence may be incomplete.")

        for item in phishing_analysis.indicators:
            is_url_structure = item.type in _URL_STRUCTURE_STRENGTHS
            source = "url_analysis" if is_url_structure else "phishing_analysis"
            strength = _URL_STRUCTURE_STRENGTHS.get(
                item.type, max(0, min(25, item.score_contribution))
            )
            add(
                source,
                item.type,
                item.severity,
                item.description,
                item.evidence,
                strength=strength,
                group=self._correlation_group(item.type, source),
                order=0 if is_url_structure else 1,
            )
        if not phishing_analysis.indicators:
            add(
                "phishing_analysis",
                "heuristic_checks_completed",
                "info",
                "Deterministic phishing URL heuristics completed without matching an indicator.",
                "No heuristic indicators matched; this does not establish safety.",
                order=1,
            )

        fraudurl = phishing_analysis.fraudurl
        fraud_probability = self._probability(fraudurl.result)
        fraud_verdict = (
            str(fraudurl.result.get("fraud_verdict", "")).strip().upper()
            if fraudurl.result
            else ""
        )
        if fraudurl.status == "ok" and fraud_probability is not None:
            # The model is one fallible signal. Values above 0.5 add risk strength;
            # lower values are capped counterevidence and never mean "safe".
            if fraud_probability >= 0.5:
                strength = (fraud_probability - 0.5) * 40
                mitigation = 0
                description = "fraudurl phishing probability, weighted as one independent model signal."
            else:
                strength = 0
                mitigation = round((0.5 - fraud_probability) * 20)
                description = (
                    "fraudurl returned a lower phishing probability; this is limited counterevidence, not proof of safety."
                )
                if mitigation > 0:
                    limitations.append(
                        "A lower fraudurl probability is limited counterevidence and does not establish that the URL is safe."
                    )
            add(
                "phishing_analysis",
                "fraudurl_probability",
                "medium" if fraud_probability >= 0.5 else "low",
                description,
                f"fraud_probability={fraud_probability:.3f}; verdict={fraud_verdict or 'unavailable'}",
                strength=strength,
                mitigation=mitigation,
                group="fraudurl_model",
                order=2,
            )
        elif fraudurl.status == "ok" and fraud_verdict in {"FRAUD", "PHISHING"}:
            add(
                "phishing_analysis",
                "fraudurl_verdict",
                "high",
                "fraudurl returned a phishing verdict without a usable probability.",
                f"verdict={fraud_verdict}; probability unavailable",
                strength=25,
                group="fraudurl_model",
                order=2,
            )
        elif fraudurl.status == "ok" and fraudurl.score_contribution > 0:
            add(
                "phishing_analysis",
                "fraudurl_score",
                "medium",
                "fraudurl returned a positive score without a usable probability; it is capped as one model signal.",
                f"score_contribution={fraudurl.score_contribution}; verdict={fraud_verdict or 'unavailable'}",
                strength=min(30, fraudurl.score_contribution),
                group="fraudurl_model",
                order=2,
            )
        elif fraudurl.status == "ok" and fraud_verdict in {"LEGITIMATE", "BENIGN"}:
            add(
                "phishing_analysis",
                "fraudurl_verdict",
                "low",
                "fraudurl returned a benign verdict without a usable probability; this is limited counterevidence.",
                f"verdict={fraud_verdict}; probability unavailable",
                mitigation=5,
                group="fraudurl_model",
                order=2,
            )
        elif fraudurl.status == "ok":
            add(
                "phishing_analysis",
                "fraudurl_result_unscorable",
                "info",
                "fraudurl returned no usable probability or recognized verdict.",
                "The detector result was not converted into risk points.",
                order=2,
            )
            limitations.append("fraudurl returned no usable probability or verdict.")
        elif fraudurl.status != "skipped":
            add(
                "phishing_analysis",
                "fraudurl_unavailable",
                "info",
                "The fraudurl model did not provide a usable result; this adds no risk points.",
                fraudurl.status,
                order=2,
            )
            limitations.append("The fraudurl phishing signal was unavailable.")

        component_score = sum(item.score_contribution for item in phishing_analysis.indicators)
        add(
            "phishing_analysis",
            "phishing_summary_score",
            "info",
            "The analyzer summary score and suspicious flag are represented by the component indicators and fraudurl signal; the summary is not added again.",
            f"is_suspicious={phishing_analysis.is_suspicious}; reported_score={phishing_analysis.score}; "
            f"indicator_points={component_score}; fraudurl_score={fraudurl.score_contribution}",
            order=2,
        )

        dns_has_errors = bool(dns_analysis.errors) or dns_analysis.status in {"error", "partial"}
        if dns_analysis.status != "not_applicable":
            record_counts = (
                f"A={len(dns_analysis.ipv4_addresses)}, AAAA={len(dns_analysis.ipv6_addresses)}, "
                f"CNAME={'present' if dns_analysis.cname_target else 'absent'}, "
                f"MX={len(dns_analysis.mail_servers)}, NS={len(dns_analysis.nameservers)}, "
                f"TXT={len(dns_analysis.txt_records)}"
            )
            if dns_analysis.errors:
                record_counts += "; errors=" + ", ".join(
                    f"{error.record_type}:{error.error_type}" for error in dns_analysis.errors
                )
            add(
                "dns_analysis",
                "dns_records_observed" if dns_analysis.resolution_succeeded else "dns_lookup_incomplete",
                "info",
                (
                    "DNS lookup completed; record existence is not treated as suspicious evidence."
                    if dns_analysis.resolution_succeeded
                    else "DNS lookup did not complete; no risk points are added."
                ),
                f"status={dns_analysis.status}; {record_counts}",
                order=3,
            )
        if dns_has_errors:
            limitations.append("DNS lookups were incomplete, so DNS evidence may be missing.")

        if tls_analysis is None:
            if url_analysis.scheme == "https":
                limitations.append("TLS analysis was unavailable for this HTTPS URL.")
        elif tls_analysis.status != "not_applicable":
            for finding in tls_analysis.findings:
                add(
                    "tls_analysis",
                    finding.type,
                    finding.severity,
                    finding.description,
                    finding.evidence,
                    strength=_TLS_RISK_STRENGTHS.get(finding.type, 0),
                    group=self._tls_correlation_group(finding.type),
                    order=4,
                )
            if tls_analysis.connection_successful and not tls_analysis.findings:
                add(
                    "tls_analysis",
                    "verified_tls_transport",
                    "info",
                    "TLS transport and certificate verification completed; this does not prove site legitimacy.",
                    self._tls_metadata(tls_analysis),
                    order=4,
                )
            elif tls_analysis.connection_successful:
                add(
                    "tls_analysis",
                    "tls_transport_metadata",
                    "info",
                    "TLS transport and certificate metadata were retrieved; these properties do not prove site legitimacy.",
                    self._tls_metadata(tls_analysis),
                    order=4,
                )
            if tls_analysis.supported and not tls_analysis.connection_successful:
                add(
                    "tls_analysis",
                    "tls_analysis_incomplete",
                    "info",
                    "TLS inspection did not complete; transport metadata is unavailable and adds no risk points by itself.",
                    tls_analysis.status,
                    order=4,
                )
                limitations.append(
                    "TLS certificate details may be unavailable because the TLS connection did not complete."
                )
            if any(finding.type == "certificate_data_unavailable" for finding in tls_analysis.findings):
                limitations.append("The TLS connection succeeded, but certificate metadata was unavailable.")
            if tls_analysis.supported:
                if tls_analysis.certificate_transparency.status != "checked":
                    limitations.append("Certificate Transparency logs were not checked.")
                if tls_analysis.certificate_revocation.status != "checked":
                    limitations.append("Certificate revocation and distrust sources were not checked.")

        if http_analysis is None:
            if url_analysis.is_valid and url_analysis.scheme in {"http", "https"}:
                limitations.append("HTTP response analysis was unavailable for this URL.")
        elif http_analysis.status != "not_applicable":
            if http_analysis.request_successful:
                present_headers = sorted(
                    name for name, value in http_analysis.security_headers.items() if value
                )
                add(
                    "http_analysis",
                    "http_response_metadata_received",
                    "info",
                    "HTTP response metadata was retrieved without reading a body or following redirects.",
                    f"status={http_analysis.status_code}; method={http_analysis.request_method}",
                    order=5,
                )
                if present_headers:
                    add(
                        "http_analysis",
                        "security_headers_observed",
                        "info",
                        "Security-relevant response headers were observed; their presence does not establish site legitimacy.",
                        ", ".join(present_headers),
                        order=5,
                    )
            else:
                add(
                    "http_analysis",
                    "http_response_unavailable",
                    "info",
                    "HTTP response metadata could not be collected; failure adds no risk points.",
                    http_analysis.error or http_analysis.status,
                    order=5,
                )
                limitations.append(
                    "HTTP response metadata could not be collected, so response-header and redirect evidence is unavailable."
                )
            for finding in http_analysis.findings:
                add(
                    "http_analysis",
                    finding.type,
                    finding.severity,
                    finding.description,
                    finding.evidence,
                    strength=self._http_strength(finding.type, finding.score_contribution),
                    group=self._http_correlation_group(finding.type),
                    order=5,
                )

        exact_url_match = (
            threat_intelligence is not None
            and threat_intelligence.status is ThreatIntelStatus.MATCHED
            and threat_intelligence.matched is True
            and threat_intelligence.match_scope == "url"
        )
        if threat_intelligence is None:
            add(
                "threat_intelligence",
                "threat_intelligence_unavailable",
                "info",
                "Threat intelligence was not available; no risk points are added.",
                "No provider result was supplied.",
                order=6,
            )
            limitations.append("Threat intelligence is unavailable; no provider conclusion can be drawn.")
        elif threat_intelligence.status is ThreatIntelStatus.MATCHED and threat_intelligence.matched:
            confidence_factor = (
                threat_intelligence.confidence
                if threat_intelligence.confidence is not None
                else 0.75
            )
            exact = threat_intelligence.match_scope == "url"
            base_strength = _THREAT_EXACT_STRENGTH if exact else _THREAT_HOST_STRENGTH
            add(
                threat_intelligence.source,
                "known_malicious_url" if exact else "known_malicious_host",
                "critical" if exact else "high",
                (
                    "Threat intelligence has an exact match for the submitted URL."
                    if exact
                    else "Threat intelligence associates this hostname with a reported malicious URL."
                ),
                f"scope={threat_intelligence.match_scope}; threat={threat_intelligence.threat_type or 'unspecified'}; "
                f"confidence={confidence_factor:.2f}; reference={threat_intelligence.reference or 'unavailable'}",
                strength=base_strength * confidence_factor,
                group="threat_intelligence",
                order=6,
            )
        elif threat_intelligence.status is ThreatIntelStatus.NO_MATCH:
            add(
                threat_intelligence.source,
                "threat_intelligence_no_match",
                "info",
                "The provider returned no match; absence of a match is not evidence that the URL is safe.",
                "No known indicator matched this lookup.",
                order=6,
            )
            limitations.append(
                f"{threat_intelligence.source} returned no match; this does not establish that the URL is safe."
            )
        else:
            add(
                threat_intelligence.source,
                "threat_intelligence_unavailable",
                "info",
                "Threat intelligence was unavailable; provider failure adds no risk points.",
                threat_intelligence.error or "Provider lookup did not complete.",
                order=6,
            )
            limitations.append(
                threat_intelligence.error
                or "Threat intelligence is unavailable; no provider conclusion can be drawn."
            )

        evidence, score = self._aggregate(signals)
        classification = (
            RiskClassification.CONFIRMED_MALICIOUS
            if exact_url_match and score >= _CONFIRMED_SCORE_THRESHOLD
            else self._classify(score)
        )
        confidence = self._confidence(
            url_analysis,
            dns_analysis,
            phishing_analysis,
            tls_analysis,
            http_analysis,
            threat_intelligence,
            signals,
        )
        if classification in {
            RiskClassification.SUSPICIOUS,
            RiskClassification.HIGH_RISK,
            RiskClassification.CONFIRMED_MALICIOUS,
        }:
            precautions = [
                "Do not enter credentials or payment details unless you independently verify the site.",
                "Use a known official website or contact channel instead of following this link.",
            ]
        else:
            precautions = [
                "Treat the URL as unverified; review available evidence before interacting with it."
            ]

        return RiskAssessment(
            classification=classification,
            score=score,
            confidence=confidence,
            contributing_indicators=evidence,
            recommended_precautions=precautions,
            limitations=list(dict.fromkeys(limitations)),
        )

    def assess_message(
        self,
        indicators: list[MessageIndicator],
        intelligence: list[ThreatIntelResult],
        ai_explanation: AIExplanation,
    ) -> RiskAssessment:
        """Score deterministic message and URL intelligence with the shared aggregation rules."""
        strengths = {
            "urgency": 10,
            "payment_request": 20,
            "credential_request": 25,
            "sensitive_information_request": 20,
            "impersonation": 22,
            "suspicious_link_present": 10,
            "attachment_reference": 6,
        }
        signals: list[_RiskSignal] = []
        limitations = [
            "Suspicious language is not proof of fraud.",
            "Absence of a threat-intelligence match is not proof that the message is safe.",
            "AI interpretation is advisory and cannot establish a verified threat.",
        ]
        for item in indicators:
            strength = strengths.get(item.category, 0)
            signals.append(_RiskSignal(
                evidence=RiskEvidence(source="message_analysis", indicator=item.category, severity=item.severity, weight=0, description=item.description, evidence=item.evidence),
                strength=strength,
                correlation_group=("message_social_engineering" if item.category in {"urgency", "payment_request", "credential_request", "sensitive_information_request", "impersonation"} else f"message:{item.category}"),
                order=0,
            ))
        exact_match = False
        for result in intelligence:
            if result.status is ThreatIntelStatus.MATCHED and result.matched:
                exact = result.match_scope == "url"
                exact_match = exact_match or exact
                factor = result.confidence if result.confidence is not None else 0.75
                strength = (_THREAT_EXACT_STRENGTH if exact else _THREAT_HOST_STRENGTH) * factor
                description = "Threat intelligence has an exact match for a URL extracted from the message." if exact else "Threat intelligence associates a hostname extracted from the message with a reported threat."
                detail = f"scope={result.match_scope}; threat={result.threat_type or 'unspecified'}; confidence={factor:.2f}; reference={result.reference or 'unavailable'}; checked_at={result.checked_at.isoformat()}"
                signals.append(_RiskSignal(evidence=RiskEvidence(source=result.source, indicator="known_malicious_url" if exact else "known_malicious_host", severity="critical" if exact else "high", weight=0, description=description, evidence=detail), strength=strength, correlation_group="message_threat_intelligence", order=1))
            elif result.status is ThreatIntelStatus.NO_MATCH:
                signals.append(_RiskSignal(evidence=RiskEvidence(source=result.source, indicator="threat_intelligence_no_match", severity="info", weight=0, description="The provider returned no match; absence of a match is not evidence that the message is safe.", evidence=f"indicator={result.indicator}; checked_at={result.checked_at.isoformat()}"), order=1))
                limitations.append(f"{result.source} returned no match for {result.indicator}; this does not establish safety.")
            else:
                signals.append(_RiskSignal(evidence=RiskEvidence(source=result.source, indicator="threat_intelligence_unavailable", severity="info", weight=0, description="Threat intelligence was unavailable; provider failure adds no risk points.", evidence=result.error or result.indicator), order=1))
                limitations.append(f"{result.source} was unavailable for an extracted URL.")
        if not intelligence:
            limitations.append("No URL threat-intelligence checks were available.")
        if ai_explanation.status != "available":
            limitations.extend(ai_explanation.limitations or ["AI explanation was unavailable."])
        else:
            ai_findings = list(dict.fromkeys(
                item.strip()[:500]
                for item in ai_explanation.suspicious_indicators
                if item.strip()
            ))[:4]
            for finding in ai_findings:
                confidence_note = (
                    f"; model_confidence={ai_explanation.confidence:.2f}"
                    if ai_explanation.confidence is not None
                    else ""
                )
                signals.append(_RiskSignal(
                    evidence=RiskEvidence(
                        source="ai_interpretation",
                        indicator="ai_suspicious_indicator",
                        severity="medium",
                        weight=0,
                        description="The AI overview identified a suspicious message characteristic; this is advisory evidence.",
                        evidence=f"{finding}{confidence_note}",
                    ),
                    strength=20,
                    correlation_group="ai_interpretation",
                    order=2,
                ))
            if ai_findings:
                limitations.append(
                    "AI-identified message characteristics contribute a capped, advisory amount to the risk score."
                )
        evidence, score = self._aggregate(signals)
        classification = RiskClassification.CONFIRMED_MALICIOUS if exact_match and score >= _CONFIRMED_SCORE_THRESHOLD else self._classify(score)
        coverage = 0.65 if ai_explanation.status != "available" else 0.85
        if intelligence:
            coverage = (coverage + (sum(item.status is not ThreatIntelStatus.UNAVAILABLE for item in intelligence) / len(intelligence))) / 2
        if not indicators and not intelligence:
            coverage = min(coverage, 0.35)
        precautions = ["Do not reply, open links, or share credentials/payment details until you verify the sender through an independent official channel."]
        return RiskAssessment(classification=classification, score=score, confidence=round(min(0.95, coverage), 2), contributing_indicators=evidence, recommended_precautions=precautions, limitations=list(dict.fromkeys(limitations)))

    @staticmethod
    def _aggregate(signals: list[_RiskSignal]) -> tuple[list[RiskEvidence], int]:
        ordered = sorted(
            signals,
            key=lambda item: (
                item.order,
                item.correlation_group,
                -item.strength,
                item.evidence.indicator,
                item.evidence.source,
                item.evidence.evidence,
            ),
        )
        score = 0
        family_counts: dict[str, int] = {}
        seen_evidence: set[tuple[str, str]] = set()
        weighted: list[RiskEvidence] = []

        for signal in ordered:
            semantic_key = (signal.evidence.indicator, signal.evidence.evidence.casefold())
            is_duplicate = semantic_key in seen_evidence
            contribution = 0
            if signal.strength > 0 and not is_duplicate:
                count = family_counts.get(signal.correlation_group, 0)
                factor = _CORRELATION_FACTORS[min(count, len(_CORRELATION_FACTORS) - 1)]
                adjusted_strength = min(95.0, signal.strength * factor)
                updated_score = round(
                    100 - (100 - score) * (1 - adjusted_strength / 100)
                )
                contribution = updated_score - score
                score = updated_score
                family_counts[signal.correlation_group] = count + 1
            if signal.mitigation > 0 and not is_duplicate:
                updated_score = max(0, score - signal.mitigation)
                contribution = updated_score - score
                score = updated_score
            if signal.strength > 0 or signal.mitigation > 0:
                seen_evidence.add(semantic_key)
            weighted.append(signal.evidence.model_copy(update={"weight": contribution}))
        return weighted, score

    @staticmethod
    def _probability(result: dict[str, object] | None) -> float | None:
        if result is None:
            return None
        value = result.get("fraud_probability")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None
        probability = float(value)
        if not math.isfinite(probability):
            return None
        return max(0.0, min(1.0, probability))

    @staticmethod
    def _tls_metadata(tls_analysis: TlsAnalysisResult) -> str:
        certificate = tls_analysis.certificate
        return (
            f"protocol={tls_analysis.protocol_version or 'unavailable'}; "
            f"certificate_verified={tls_analysis.certificate_verified}; "
            f"hostname_matches={certificate.hostname_matches if certificate else 'unknown'}; "
            f"issuer={certificate.issuer if certificate else 'unavailable'}; "
            f"not_after={certificate.not_after if certificate else 'unavailable'}; "
            f"expired={certificate.is_expired if certificate else 'unknown'}; "
            f"public_key={certificate.public_key_algorithm if certificate else 'unavailable'}"
            f"/{certificate.public_key_size if certificate else 'unknown'}; "
            f"signature={certificate.signature_algorithm if certificate else 'unavailable'}; "
            f"chain_entries={len(tls_analysis.certificate_chain)}; "
            f"CT={tls_analysis.certificate_transparency.status}; "
            f"revocation={tls_analysis.certificate_revocation.status}"
        )

    @staticmethod
    def _correlation_group(indicator: str, source: str) -> str:
        if source == "url_analysis":
            if indicator in {
                "ip_hostname",
                "punycode_hostname",
                "excessive_subdomains",
                "misleading_hostname_structure",
                "long_hostname",
                "typosquatting_domain",
                "brand_impersonation_domain",
            }:
                return "url_hostname_structure"
            if indicator == "unusual_port":
                return "url_port"
            return "url_obfuscation"
        if indicator == "suspicious_keyword":
            return "phishing_keyword"
        return f"{source}:{indicator}"

    @staticmethod
    def _tls_correlation_group(indicator: str) -> str:
        if indicator in {"hostname_mismatch", "certificate_verification_failed"}:
            return "tls_identity"
        if indicator in {
            "certificate_expired",
            "certificate_not_yet_valid",
            "certificate_expires_soon",
        }:
            return "tls_validity"
        if indicator in {
            "weak_public_key",
            "weak_signature_algorithm",
            "obsolete_tls_version",
        }:
            return "tls_cryptography"
        return f"tls:{indicator}"

    @staticmethod
    def _http_strength(indicator: str, analyzer_strength: int) -> int:
        known_strengths = {
            "insecure_http": 10,
            "missing_hsts": 2,
            "missing_content_security_policy": 2,
            "missing_nosniff": 1,
            "missing_frame_protection": 1,
            "missing_referrer_policy": 1,
            "redirect_without_location": 3,
            "https_downgrade_redirect": 12,
            "cross_origin_redirect": 3,
            "location_without_redirect_status": 2,
        }
        return known_strengths.get(indicator, max(0, min(25, analyzer_strength)))

    @staticmethod
    def _http_correlation_group(indicator: str) -> str:
        if indicator in {"insecure_http", "https_downgrade_redirect"}:
            return "http_transport_security"
        if indicator in {
            "missing_hsts",
            "missing_content_security_policy",
            "missing_nosniff",
            "missing_frame_protection",
            "missing_referrer_policy",
        }:
            return "http_security_headers"
        if indicator in {
            "redirect_without_location",
            "cross_origin_redirect",
            "location_without_redirect_status",
        }:
            return "http_redirect_behavior"
        return f"http:{indicator}"

    @staticmethod
    def _confidence(
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult,
        phishing_analysis: PhishingAnalysisResult,
        tls_analysis: TlsAnalysisResult | None,
        http_analysis: HttpAnalysisResult | None,
        threat_intelligence: ThreatIntelResult | None,
        signals: list[_RiskSignal],
    ) -> float:
        coverage: list[float] = [1.0]  # URL structure parsing always ran.
        if dns_analysis.status != "not_applicable":
            if dns_analysis.resolution_succeeded:
                coverage.append(0.6 if dns_analysis.status == "partial" else 1.0)
            else:
                coverage.append(0.0)

        coverage.append(1.0 if url_analysis.is_valid else 0.0)  # deterministic phishing rules
        if url_analysis.is_valid:
            fraud_result = phishing_analysis.fraudurl.result
            fraud_verdict = (
                str(fraud_result.get("fraud_verdict", "")).strip().upper()
                if fraud_result
                else ""
            )
            fraud_usable = (
                RiskScorer._probability(fraud_result) is not None
                or fraud_verdict in {"FRAUD", "PHISHING", "LEGITIMATE", "BENIGN"}
                or phishing_analysis.fraudurl.score_contribution > 0
            )
            coverage.append(
                1.0
                if phishing_analysis.fraudurl.status == "ok" and fraud_usable
                else 0.5
                if phishing_analysis.fraudurl.status == "ok"
                else 0.0
            )

        if url_analysis.scheme == "https":
            coverage.append(
                1.0
                if tls_analysis is not None and tls_analysis.connection_successful
                else 0.5
                if tls_analysis is not None
                and tls_analysis.supported
                and any(
                    _TLS_RISK_STRENGTHS.get(finding.type, 0) > 0
                    for finding in tls_analysis.findings
                )
                else 0.0
            )
        if url_analysis.is_valid and url_analysis.scheme in {"http", "https"}:
            coverage.append(
                1.0
                if http_analysis is not None and http_analysis.request_successful
                else 0.0
            )
        if threat_intelligence is None:
            coverage.append(0.0)
        elif threat_intelligence.status is ThreatIntelStatus.UNAVAILABLE:
            coverage.append(0.0)
        elif threat_intelligence.status is ThreatIntelStatus.MATCHED:
            coverage.append(
                threat_intelligence.confidence
                if threat_intelligence.confidence is not None
                else 1.0
            )
        else:
            coverage.append(1.0)

        confidence = sum(coverage) / len(coverage) if coverage else 0.0
        has_counterevidence = any(signal.mitigation > 0 for signal in signals)
        has_risk_evidence = any(signal.strength > 0 for signal in signals)
        if has_counterevidence and has_risk_evidence:
            confidence *= 0.9
        return round(min(0.95, max(0.0, confidence)), 2)

    @staticmethod
    def _classify(score: int) -> RiskClassification:
        if score < 15:
            return RiskClassification.LOW_RISK
        if score < 35:
            return RiskClassification.SUSPICIOUS
        return RiskClassification.HIGH_RISK
