import type { RiskEvidence, SummaryFinding, Tone, UrlAnalysisResponse } from "../types/investigation";

export function toneForRisk(classification: string): Tone {
  if (classification === "Confirmed Malicious" || classification === "High Risk") return "danger";
  if (classification === "Suspicious") return "warning";
  if (classification === "Low Risk") return "good";
  return "neutral";
}

export function statusTone(status: string): Tone {
  if (["matched", "error", "failed", "expired"].includes(status.toLowerCase())) return "danger";
  if (["warning", "suspicious"].includes(status.toLowerCase())) return "warning";
  if (["unavailable", "partial", "not_applicable", "not checked"].includes(status.toLowerCase())) {
    return "warning";
  }
  if (["ok", "no_match", "successful", "checked"].includes(status.toLowerCase())) return "good";
  return "neutral";
}

export function shortEvidenceTitle(item: RiskEvidence): string {
  if (item.indicator === "fraudurl_probability" || item.indicator === "fraudurl_verdict") {
    return "Fraud detection";
  }
  if (item.indicator.startsWith("known_malicious")) return "Threat intelligence match";
  if (item.indicator === "typosquatting_domain") return "Possible typosquatting";
  if (item.source === "tls_analysis") return "Certificate security";
  if (item.source === "http_analysis") return "HTTP response security";
  if (item.indicator === "suspicious_keyword") return "Suspicious URL wording";
  return item.source.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function shortEvidenceDescription(item: RiskEvidence): string {
  if (item.indicator === "fraudurl_probability") {
    const probability = /fraud_probability=([0-9]*\.?[0-9]+)/.exec(item.evidence)?.[1];
    if (probability !== undefined) {
      return `The URL detector estimated ${(Number(probability) * 100).toFixed(1)}% phishing probability.`;
    }
  }
  return item.description;
}

export function keyFindings(result: UrlAnalysisResponse): SummaryFinding[] {
  const findings: SummaryFinding[] = [];
  const add = (finding: SummaryFinding) => {
    if (!findings.some((existing) => existing.title === finding.title)) findings.push(finding);
  };

  if (
    result.typosquatting.detected &&
    (result.typosquatting.domain || result.typosquatting.submitted_domain) &&
    (result.typosquatting.reference_domain || result.typosquatting.possible_intended_site)
  ) {
    const domain = result.typosquatting.domain ?? result.typosquatting.submitted_domain!;
    const reference = result.typosquatting.reference_domain ?? result.typosquatting.possible_intended_site!;
    const brandImpersonation = ["misleading_subdomain", "brand_action_domain"].includes(
      result.typosquatting.technique ?? "",
    );
    const technique = result.typosquatting.technique?.replaceAll("_", " ") ?? "domain similarity";
    add({
      title: brandImpersonation ? "Possible brand impersonation" : "Possible typosquatting",
      detail: `${domain} is similar to ${reference} · ${technique}${result.typosquatting.evidence ? ` · ${result.typosquatting.evidence}` : ""}`,
      details: result.typosquatting,
      tone: "warning",
    });
  }

  const impactfulEvidence = [...result.risk_assessment.contributing_indicators]
    .filter((item) => item.weight !== 0 && item.indicator !== "typosquatting_domain")
    .sort((left, right) => Math.abs(right.weight) - Math.abs(left.weight));
  for (const item of impactfulEvidence) {
    if (findings.length >= 4) break;
    add({
      title: shortEvidenceTitle(item),
      detail: shortEvidenceDescription(item),
      details: item,
      tone: item.weight < 0 ? "good" : "warning",
    });
  }

  const threat = result.threat_intelligence;
  if (findings.length < 4 && !findings.some((item) => item.title === "Threat intelligence match")) {
    add({
      title: "Threat intelligence",
      detail:
        threat.status === "no_match"
          ? `${threat.source} returned no known match. This does not establish that the site is safe.`
          : threat.status === "unavailable"
            ? `${threat.source} could not be reached for a lookup.`
            : `${threat.source} reported a match${threat.threat_type ? `: ${threat.threat_type.replaceAll("_", " ")}` : "."}`,
      details: threat,
      tone:
        threat.status === "matched"
          ? "danger"
          : threat.status === "unavailable"
            ? "neutral"
            : "info",
    });
  }

  if (findings.length < 4) {
    const tls = result.tls_analysis;
    if (tls.status === "not_applicable") {
      add({
        title: "TLS",
        detail: "This URL uses HTTP, so a TLS check does not apply.",
        details: tls,
        tone: "neutral",
      });
    } else if (tls.connection_successful && tls.certificate_verified === true) {
      add({
        title: "HTTPS transport",
        detail: `TLS connection and certificate verification succeeded${tls.protocol_version ? ` (${tls.protocol_version})` : ""}. This does not establish site legitimacy.`,
        details: tls,
        tone: "good",
      });
    } else if (!tls.connection_successful) {
      add({
        title: "TLS check",
        detail: "The certificate connection could not be verified.",
        details: tls,
        tone: "neutral",
      });
    }
  }

  if (findings.length < 4) {
    const http = result.http_analysis;
    add({
      title: "HTTP response",
      detail: http.request_successful
        ? `Response metadata received${http.status_code === null ? "." : ` (HTTP ${http.status_code}${httpStatusText(http.status_code) ? ` ${httpStatusText(http.status_code)}` : ""}).`}`
        : "Response metadata could not be collected.",
      details: http,
      tone: http.request_successful ? "good" : "neutral",
    });
  }

  return findings.slice(0, 4);
}

export function httpStatusText(status: number): string {
  const labels: Record<number, string> = {
    200: "OK",
    201: "Created",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
  };
  return labels[status] ?? "";
}

