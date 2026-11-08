from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Protocol

from app.analyzers.typosquatting import detect_lookalike_domain
from app.models.phishing import (
    FraudUrlSignal,
    PhishingAnalysisResult,
    PhishingIndicator,
    TyposquattingAnalysis,
)
from app.models.url import UrlAnalysisResult

_DEFAULT_KEYWORDS = frozenset(
    {
        "account",
        "auth",
        "billing",
        "confirm",
        "credential",
        "login",
        "password",
        "payment",
        "secure",
        "signin",
        "support",
        "update",
        "verify",
    }
)
_ENCODED_SPECIAL = re.compile(r"%(?:2e|2f|40|3a|5c)", re.IGNORECASE)
_SPECIAL_CHARACTERS = frozenset("@%!?=;_~,")
_DOMAIN_LIKE_LABELS = frozenset({"com", "net", "org", "co", "gov", "edu"})
_STANDARD_PORTS = {"http": 80, "https": 443}
_FRAUDURL_TIMEOUT_SECONDS = 3.0
_MAX_FRAUDURL_OUTPUT_BYTES = 64_000


class FraudUrlAnalyzer(Protocol):
    def analyze(self, url: str) -> FraudUrlSignal: ...


class FraudUrlAdapter:
    """Call fraudurl's documented offline JSON CLI without shell execution."""

    def analyze(self, url: str) -> FraudUrlSignal:
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "fraudurl", "--url", url, "--quiet"],
                capture_output=True,
                check=False,
                text=True,
                timeout=_FRAUDURL_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                return FraudUrlSignal(
                    status="error",
                    error=(completed.stderr.strip() or "fraudurl exited unsuccessfully")[:500],
                )
            if len(completed.stdout.encode("utf-8")) > _MAX_FRAUDURL_OUTPUT_BYTES:
                return FraudUrlSignal(status="error", error="fraudurl output exceeded the limit")
            result = json.loads(completed.stdout)
            if not isinstance(result, dict):
                return FraudUrlSignal(status="error", error="fraudurl returned an invalid result")
            probability = result.get("fraud_probability")
            contribution = (
                max(0, min(30, round(float(probability) * 30)))
                if isinstance(probability, (float, int))
                else 0
            )
            return FraudUrlSignal(
                status="ok",
                result=result,
                score_contribution=contribution,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            return FraudUrlSignal(status="error", error=f"{type(exc).__name__}: {exc}"[:500])


class PhishingAnalyzer:
    """Combine transparent URL heuristics with an isolated fraudurl signal."""

    def __init__(
        self,
        *,
        keywords: set[str] | frozenset[str] | None = None,
        fraudurl_analyzer: FraudUrlAnalyzer | None = None,
    ) -> None:
        configured_keywords = _DEFAULT_KEYWORDS if keywords is None else keywords
        self._keywords = frozenset(keyword.lower() for keyword in configured_keywords)
        self._fraudurl = (
            fraudurl_analyzer if fraudurl_analyzer is not None else FraudUrlAdapter()
        )

    def analyze(self, url_analysis: UrlAnalysisResult) -> PhishingAnalysisResult:
        if not url_analysis.is_valid or not url_analysis.normalized_url or not url_analysis.hostname:
            return PhishingAnalysisResult(
                is_suspicious=False,
                score=0,
                fraudurl=FraudUrlSignal(status="skipped", error="URL structure is invalid."),
            )

        url = url_analysis.normalized_url
        hostname = url_analysis.hostname.lower()
        indicators: list[PhishingIndicator] = []
        typosquatting = TyposquattingAnalysis(
            is_idn=any(label.startswith("xn--") for label in hostname.split("."))
        )

        def add(
            kind: str,
            points: int,
            description: str,
            evidence: str,
            *,
            severity: str | None = None,
        ) -> None:
            severity = severity or ("high" if points >= 20 else "medium" if points >= 12 else "low")
            indicators.append(
                PhishingIndicator(
                    type=kind,
                    severity=severity,
                    description=description,
                    evidence=evidence,
                    score_contribution=points,
                )
            )

        if len(hostname) > 45:
            add("long_hostname", 10, "Hostname is unusually long.", f"{len(hostname)} characters")

        subdomain_labels = (url_analysis.subdomain or "").split(".")
        subdomain_labels = [label for label in subdomain_labels if label]
        if len(subdomain_labels) >= 3:
            add(
                "excessive_subdomains",
                15,
                "Hostname contains many subdomain levels.",
                f"{len(subdomain_labels)} subdomain labels",
            )

        if url_analysis.is_ip_address:
            add("ip_hostname", 20, "URL uses an IP address as its hostname.", hostname)

        lookalike = detect_lookalike_domain(
            url_analysis.registered_domain,
            hostname=hostname,
            subdomain=url_analysis.subdomain,
        )
        if lookalike is not None:
            typosquatting = TyposquattingAnalysis(
                detected=True,
                submitted_domain=url_analysis.registered_domain,
                possible_intended_site=lookalike.intended_domain,
                similarity=lookalike.similarity,
                edit_distance=lookalike.edit_distance,
                domain=lookalike.suspicious_domain or url_analysis.registered_domain,
                reference_domain=lookalike.intended_domain,
                technique=lookalike.technique,
                severity=lookalike.severity,
                evidence=lookalike.evidence,
                is_idn=lookalike.idn,
            )
            indicator_type = (
                "brand_impersonation_domain"
                if lookalike.technique in {"misleading_subdomain", "brand_action_domain"}
                else "typosquatting_domain"
            )
            # Brand-like subdomains and action-word variants reuse the existing
            # 15-point structural-signal weight; close registrable-domain typos
            # keep the established typosquatting weight.
            points = 15 if indicator_type == "brand_impersonation_domain" else 30
            add(
                indicator_type,
                points,
                f"{lookalike.suspicious_domain} may impersonate {lookalike.intended_domain} "
                f"using {lookalike.technique.replace('_', ' ')}.",
                f"registered_domain={url_analysis.registered_domain}; "
                f"possible_intended_site={lookalike.intended_domain}; "
                f"domain={lookalike.suspicious_domain}; reference_domain={lookalike.intended_domain}; "
                f"technique={lookalike.technique}; similarity={lookalike.similarity:.2f}; "
                f"edit_distance={lookalike.edit_distance}; {lookalike.evidence}",
                severity=lookalike.severity,
            )

        if url_analysis.has_username:
            add(
                "embedded_username",
                20,
                "URL embeds user information before the hostname.",
                "Username is present in the URL authority.",
            )

        encoded_matches = _ENCODED_SPECIAL.findall(url)
        if len(encoded_matches) >= 2:
            add(
                "suspicious_encoding",
                12,
                "URL encodes multiple characters that can obscure its structure.",
                f"{len(encoded_matches)} encoded separators or delimiters",
            )

        special_count = sum(character in _SPECIAL_CHARACTERS for character in url)
        if special_count >= 12:
            add(
                "excessive_special_characters",
                10,
                "URL contains an unusually high number of special characters.",
                f"{special_count} selected special characters",
            )

        keyword_matches = sorted(
            keyword
            for keyword in self._keywords
            if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", url.lower())
        )
        if keyword_matches:
            add(
                "suspicious_keyword",
                12,
                "URL contains words commonly used in account or payment lures.",
                ", ".join(keyword_matches),
            )

        if len(url) > 200:
            add("long_url", 10, "URL is unusually long.", f"{len(url)} characters")

        if "xn--" in hostname:
            add(
                "punycode_hostname",
                0,
                "Hostname contains an internationalized punycode label; this alone is not evidence of impersonation.",
                hostname,
                severity="info",
            )

        if url_analysis.subdomain:
            labels = set(url_analysis.subdomain.lower().split("."))
            misleading_labels = sorted(labels & _DOMAIN_LIKE_LABELS)
            if misleading_labels:
                add(
                    "misleading_hostname_structure",
                    15,
                    "Subdomain contains a label that resembles a domain suffix.",
                    ", ".join(misleading_labels),
                )

        standard_port = _STANDARD_PORTS.get(url_analysis.scheme or "")
        if url_analysis.port is not None and url_analysis.port != standard_port:
            add(
                "unusual_port",
                10,
                "URL uses a non-standard web port.",
                str(url_analysis.port),
            )

        try:
            fraudurl = self._fraudurl.analyze(url)
        except Exception as exc:
            fraudurl = FraudUrlSignal(
                status="error",
                error=f"{type(exc).__name__}: {exc}"[:500],
            )

        score = min(100, sum(item.score_contribution for item in indicators) + fraudurl.score_contribution)
        return PhishingAnalysisResult(
            is_suspicious=score >= 25,
            score=score,
            indicators=indicators,
            fraudurl=fraudurl,
            typosquatting=typosquatting,
        )
