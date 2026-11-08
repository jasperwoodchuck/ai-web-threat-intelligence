import { EmptyState } from "../ui/EmptyState";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Badge as Pill } from "../ui/Badge";
import type { FileAnalysisResponse, MessageAnalysisResponse, UrlAnalysisResponse, WebsiteAvailability } from "../../types/investigation";
import { ValueList } from "./ResultPrimitives";
import { UrlInvestigationReport } from "./UrlInvestigationReport";
import { toneForRisk } from "../../lib/analysis";

type InvestigationResultsProps = {
  result: UrlAnalysisResponse | null;
  availability: WebsiteAvailability | null;
  fileResult: FileAnalysisResponse | null;
  messageResult: MessageAnalysisResponse | null;
  error: string;
  loading: boolean;
  detailedOpen: boolean;
  setDetailedOpen: (open: boolean) => void;
  riskEvidenceOpen: boolean;
  setRiskEvidenceOpen: (open: boolean) => void;
};

export function InvestigationResults({ result, availability, fileResult, messageResult, error, loading, detailedOpen, setDetailedOpen, riskEvidenceOpen, setRiskEvidenceOpen }: InvestigationResultsProps) {

  return <>
        {availability && <section className={`availability-card availability-${availability.status}`} role="status" aria-live="polite">
          <div className="availability-icon" aria-hidden="true">{availability.status === "not_found" ? "?" : "!"}</div>
          <div className="availability-copy">
            <p className="eyebrow">WEBSITE AVAILABILITY</p>
            <h2>{availability.status === "not_found" ? "Website not found" : availability.status === "unreachable" ? "Website unreachable" : "Availability check failed"}</h2>
            <strong className="availability-domain">{availability.domain}</strong>
            <p>{availability.status === "not_found" ? "The domain could not be resolved. Check the URL and try again." : availability.status === "unreachable" ? "The domain exists, but the server could not be reached. This does not by itself indicate that the website is malicious." : "Website availability could not be determined. Retry the check."}</p>
            <p className="availability-detail">{availability.details}</p>
          </div>
        </section>}
        {error && !availability && <ErrorState message={error} />}

        {loading && <LoadingState />}
        {fileResult && !loading && <section className="message-report file-report" aria-live="polite">
          <div className="message-report-heading"><div><p className="eyebrow">FILE ANALYSIS</p><h2>Image analysis and OCR</h2></div><span className="report-target">{fileResult.filename}</span></div>
          <section className="result-section file-result-summary"><h3>Analysis summary</h3><p>{fileResult.summary || "File inspected."}</p></section>
          <section className="result-section"><h3>Extracted text</h3><pre className="ocr-output">{fileResult.extracted_text || "No readable text was identified."}</pre></section>
          <section className="result-section"><h3>Visual indicators</h3>{fileResult.indicators.length ? <ul className="file-indicator-list">{fileResult.indicators.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p className="empty-note">No additional visual indicators reported.</p>}</section>
          <section className="result-section"><h3>File metadata</h3><div className="file-metadata-grid"><div><span>Type</span><strong>{fileResult.media_type}</strong></div><div><span>Size</span><strong>{(fileResult.size_bytes / 1024 / 1024).toFixed(2)} MB</strong></div><div><span>SHA-256</span><strong>{fileResult.sha256}</strong></div></div></section>
          {!!fileResult.limitations.length && <section className="result-section"><h3>Analysis limitations</h3><ValueList items={fileResult.limitations}/></section>}
        </section>}

        {messageResult && !loading && (
          <section className="message-report" aria-live="polite">
            <div className="message-report-heading">
              <div>
                <p className="eyebrow">TEXT MESSAGE INVESTIGATION</p>
                <h2>Investigation results</h2>
              </div>
              <span className="report-target">Deterministic checks complete</span>
            </div>
            <div className="message-verdict">
              <div>
                <p className="eyebrow">OVERALL VERDICT</p>
                <h3>{messageResult.risk_assessment.classification}</h3>
                <p className="message-result-note">
                  Confidence {Math.round(messageResult.risk_assessment.confidence * 100)}%. Suspicious language is not proof of fraud.
                </p>
              </div>
              <Pill tone={toneForRisk(messageResult.risk_assessment.classification)}>
                {messageResult.risk_assessment.classification}
              </Pill>
              <strong className="message-score">{messageResult.risk_assessment.score}<small>/100</small></strong>
            </div>
            <div className="message-result-grid">
              <section className="result-section verified-message-findings">
                <div className="result-section-heading"><h3>Verified message signals</h3><span>Deterministic analysis</span></div>
                <h4>Extracted indicators</h4>
                <ValueList items={[...messageResult.extracted_urls, ...messageResult.extracted_email_addresses, ...messageResult.extracted_phone_numbers]} />
                <h4>Deterministic observations</h4>
                {messageResult.deterministic_indicators.length ? (
                  <ul className="result-list">
                    {messageResult.deterministic_indicators.map((item, index) => (
                      <li key={`${item.category}-${index}`}><strong>{item.description}</strong><span>{item.evidence}</span></li>
                    ))}
                  </ul>
                ) : <p className="empty-note">No listed deterministic indicators were observed.</p>}
                <h4>URL threat intelligence</h4>
                {messageResult.url_threat_intelligence.length ? (
                  <ul className="result-list">
                    {messageResult.url_threat_intelligence.map((item, index) => (
                      <li key={`${item.indicator}-${index}`}><strong>{item.source}: {item.status}</strong><span>{item.match_scope ? `${item.match_scope} · ` : ""}{item.indicator}</span></li>
                    ))}
                  </ul>
                ) : <p className="empty-note">No URLs were available to check.</p>}
              </section>
              <section className="result-section ai-advisory">
                <div className="ai-advisory-heading">
                  <span className="ai-advisory-mark" aria-hidden="true">✦</span>
                  <div><h3>AI interpretation</h3><span>Advisory analysis — not verified threat intelligence.</span></div>
                  <Pill tone="info">Advisory</Pill>
                </div>
                <p>{messageResult.ai_explanation.advisory_note}</p>
                <p>{messageResult.ai_explanation.summary ?? "No AI explanation available; deterministic analysis is preserved."}</p>
                <h4>Suggested indicators</h4>
                <ValueList items={messageResult.ai_explanation.suspicious_indicators} empty="No AI indicators suggested" />
                <h4>Recommended actions</h4>
                <ValueList items={messageResult.ai_explanation.recommended_actions} empty="No AI recommendations available" />
              </section>
            </div>
          </section>
        )}

        {!result && !messageResult && !fileResult && !availability && !loading && !error && <EmptyState />}

        {result && <UrlInvestigationReport result={result} detailedOpen={detailedOpen} setDetailedOpen={setDetailedOpen} riskEvidenceOpen={riskEvidenceOpen} setRiskEvidenceOpen={setRiskEvidenceOpen} />}
  </>;
}


