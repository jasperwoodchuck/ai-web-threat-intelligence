import { Badge } from "../ui/Badge";
import type { AnalysisApiResult } from "../../lib/reportExport";

type TyposquattingDisplay = {
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

function asDetectedTyposquatting(value: unknown): TyposquattingDisplay | null {
  if (!isRecord(value)) return null;
  if (!("detected" in value) || value.detected !== true) return null;
  const data = value;

  return {
    domain:
      typeof data.domain === "string" && data.domain.trim()
        ? data.domain
        : typeof data.submitted_domain === "string" && data.submitted_domain.trim()
          ? data.submitted_domain
          : null,
    referenceDomain:
      typeof data.reference_domain === "string" && data.reference_domain.trim()
        ? data.reference_domain
        : typeof data.possible_intended_site === "string" && data.possible_intended_site.trim()
          ? data.possible_intended_site
          : null,
    technique: typeof data.technique === "string" && data.technique.trim() ? data.technique : null,
    severity: typeof data.severity === "string" && data.severity.trim() ? data.severity : null,
    evidence: typeof data.evidence === "string" && data.evidence.trim() ? data.evidence : null,
    similarity:
      typeof data.similarity === "number" && Number.isFinite(data.similarity)
        ? Math.max(0, Math.min(1, data.similarity))
        : null,
  };
}

export function getTyposquattingDetection(result: AnalysisApiResult): TyposquattingDisplay | null {
  if (!("url_analysis" in result)) return null;
  return (
    asDetectedTyposquatting(result.typosquatting) ??
    asDetectedTyposquatting(result.phishing_analysis?.typosquatting)
  );
}

function formatTechnique(technique: string | null): string {
  if (!technique) return "Domain similarity";
  return technique.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function TyposquattingDetectionCard({
  detection,
}: {
  detection: TyposquattingDisplay;
}) {
  const reference = detection.referenceDomain;
  const canSuggestCorrection =
    Boolean(reference) &&
    detection.similarity !== null &&
    detection.similarity >= 0.8 &&
    detection.technique !== "misleading_subdomain" &&
    detection.technique !== "brand_action_domain";

  return (
    <section className="typosquatting-detection-card" aria-label="Typosquatting detection">
      <div className="typosquatting-card-heading">
        <span className="typosquatting-card-icon" aria-hidden="true">!</span>
        <div className="typosquatting-card-title">
          <p className="eyebrow">TYPOSQUATTING DETECTED</p>
          <h3>
            {canSuggestCorrection
              ? `Did you mean ${reference}?`
              : reference
                ? `Possible brand impersonation of ${reference}`
                : "A suspicious domain similarity was detected"}
          </h3>
        </div>
        <Badge tone="warning">{detection.severity ?? "Detected"}</Badge>
      </div>
      <dl className="typosquatting-card-details">
        <div>
          <dt>Suspicious domain</dt>
          <dd>{detection.domain ?? "Domain not returned"}</dd>
        </div>
        {reference && (
          <div>
            <dt>Reference domain</dt>
            <dd>{reference}</dd>
          </div>
        )}
        {detection.technique && (
          <div>
            <dt>Detected technique</dt>
            <dd>{formatTechnique(detection.technique)}</dd>
          </div>
        )}
        {detection.similarity !== null && (
          <div>
            <dt>Similarity</dt>
            <dd>{Math.round(detection.similarity * 100)}%</dd>
          </div>
        )}
      </dl>
      {detection.evidence && <p className="typosquatting-card-evidence">{detection.evidence}</p>}
    </section>
  );
}
