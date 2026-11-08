import type { AnalysisApiResult } from "./reportExport";

export type TyposquattingDisplay = {
  domain: string | null;
  referenceDomain: string | null;
  technique: string | null;
  severity: string | null;
  evidence: string | null;
  similarity: number | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseTyposquattingDetection(value: unknown): TyposquattingDisplay | null {
  if (!isRecord(value) || value.detected !== true) return null;

  return {
    domain:
      typeof value.domain === "string" && value.domain.trim()
        ? value.domain
        : typeof value.submitted_domain === "string" && value.submitted_domain.trim()
          ? value.submitted_domain
          : null,
    referenceDomain:
      typeof value.reference_domain === "string" && value.reference_domain.trim()
        ? value.reference_domain
        : typeof value.possible_intended_site === "string" && value.possible_intended_site.trim()
          ? value.possible_intended_site
          : null,
    technique: typeof value.technique === "string" && value.technique.trim() ? value.technique : null,
    severity: typeof value.severity === "string" && value.severity.trim() ? value.severity : null,
    evidence: typeof value.evidence === "string" && value.evidence.trim() ? value.evidence : null,
    similarity:
      typeof value.similarity === "number" && Number.isFinite(value.similarity)
        ? Math.max(0, Math.min(1, value.similarity))
        : null,
  };
}

export function getTyposquattingDetection(result: AnalysisApiResult): TyposquattingDisplay | null {
  if (!("url_analysis" in result)) return null;
  return (
    parseTyposquattingDetection(result.typosquatting) ??
    parseTyposquattingDetection(result.phishing_analysis?.typosquatting)
  );
}
