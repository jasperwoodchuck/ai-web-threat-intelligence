import { Badge } from "../ui/Badge";
import type { TyposquattingDisplay } from "../../lib/typosquatting";

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
