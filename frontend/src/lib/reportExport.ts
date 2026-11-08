import type {
  FileAnalysisResponse,
  MessageAnalysisResponse,
  RiskAssessment,
  UrlAnalysisResponse,
} from "../types/investigation";

export type AnalysisApiResult =
  | UrlAnalysisResponse
  | MessageAnalysisResponse
  | FileAnalysisResponse;

export interface SanitizedAnalysisReport {
  schema_version: "1.0";
  exported_at: string;
  analysis_type: "website" | "message" | "file";
  content_type?: string;
  risk: {
    verdict: string;
    score: number;
    score_scale: "0-100";
    confidence_percent: number;
    signal_count: number;
  };
  key_findings_count: number;
  recommended_precautions: string[];
  checks: { name: string; status: string }[];
  evidence_sources: string[];
  ai_interpretation_status: string;
  privacy_note: string;
}

function riskOf(result: AnalysisApiResult): RiskAssessment {
  return result.risk_assessment;
}

function modeAndChecks(result: AnalysisApiResult): {
  analysisType: SanitizedAnalysisReport["analysis_type"];
  contentType?: string;
  checks: SanitizedAnalysisReport["checks"];
  aiStatus: string;
} {
  if ("url_analysis" in result) {
    return {
      analysisType: "website",
      checks: [
        { name: "DNS", status: result.dns_analysis.resolution_succeeded ? "Resolved" : "Unavailable" },
        {
          name: "TLS",
          status: result.tls_analysis.certificate_verified
            ? "Verified"
            : result.tls_analysis.status === "not_applicable"
              ? "Not applicable"
              : "Unavailable",
        },
        { name: "HTTP", status: result.http_analysis.request_successful ? "Received" : "Unavailable" },
        { name: "Reputation", status: result.threat_intelligence.status.replaceAll("_", " ") },
        { name: "Phishing signals", status: result.phishing_analysis.is_suspicious ? "Detected" : "No signal" },
      ],
      aiStatus: result.ai_explanation?.status ?? "unavailable",
    };
  }

  if ("filename" in result) {
    return {
      analysisType: "file",
      contentType: result.content_type,
      checks: [
        { name: "Content classification", status: result.content_type.replaceAll("_", " ") },
        { name: "Text extraction", status: result.extracted_text ? "Text found" : "No text" },
        { name: "Links", status: `${result.extracted_urls.length} found` },
        { name: "AI interpretation", status: result.ai_explanation.status.replaceAll("_", " ") },
      ],
      aiStatus: result.ai_explanation.status,
    };
  }

  return {
    analysisType: "message",
    checks: [
      { name: "Links", status: `${result.extracted_urls.length} found` },
      {
        name: "Urgency",
        status: result.deterministic_indicators.some((item) => item.category === "urgency")
          ? "Detected"
          : "No signal",
      },
      {
        name: "Impersonation",
        status: result.deterministic_indicators.some((item) => item.category === "impersonation")
          ? "Possible"
          : "No signal",
      },
      { name: "AI interpretation", status: result.ai_explanation.status.replaceAll("_", " ") },
    ],
    aiStatus: result.ai_explanation.status,
  };
}

export function createSanitizedReport(
  result: AnalysisApiResult,
  exportedAt = new Date(),
): SanitizedAnalysisReport {
  const risk = riskOf(result);
  const { analysisType, contentType, checks, aiStatus } = modeAndChecks(result);
  const sources = new Set(risk.contributing_indicators.map((item) => item.source.trim()).filter(Boolean));
  if ("url_analysis" in result && result.threat_intelligence.source) {
    sources.add(result.threat_intelligence.source);
  } else if ("url_threat_intelligence" in result) {
    for (const item of result.url_threat_intelligence) {
      if (item.source) sources.add(item.source);
    }
  }

  const report: SanitizedAnalysisReport = {
    schema_version: "1.0",
    exported_at: exportedAt.toISOString(),
    analysis_type: analysisType,
    risk: {
      verdict: risk.classification,
      score: risk.score,
      score_scale: "0-100",
      confidence_percent: Math.round(risk.confidence * 100),
      signal_count: risk.contributing_indicators.length,
    },
    key_findings_count:
      "filename" in result
        ? result.key_findings.length
        : risk.contributing_indicators.length,
    recommended_precautions: [...risk.recommended_precautions],
    checks,
    evidence_sources: [...sources].sort(),
    ai_interpretation_status: aiStatus,
    privacy_note:
      "This export omits submitted URLs, message text, filenames, file contents, OCR text, extracted indicators, and AI prose.",
  };

  if (contentType) report.content_type = contentType;
  return report;
}

export function formatSanitizedSummary(report: SanitizedAnalysisReport): string {
  const lines = [
    "Web Threat Intelligence — Analysis Summary",
    `Exported: ${report.exported_at}`,
    `Analysis type: ${report.analysis_type}${report.content_type ? ` (${report.content_type})` : ""}`,
    `Verdict: ${report.risk.verdict}`,
    `Risk score: ${report.risk.score}/${report.risk.score_scale}`,
    `Confidence: ${report.risk.confidence_percent}% · ${report.risk.signal_count} signals`,
    `Key findings: ${report.key_findings_count}`,
    "",
    "Checks:",
    ...report.checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    `Evidence sources: ${report.evidence_sources.length ? report.evidence_sources.join(", ") : "None reported"}`,
    "",
    "Recommended precautions:",
    ...(report.recommended_precautions.length
      ? report.recommended_precautions.map((item) => `- ${item}`)
      : ["- Review the available evidence before acting."]),
    "",
    report.privacy_note,
    "Automated analysis is advisory and does not prove content is safe or malicious.",
  ];
  return lines.join("\n");
}
