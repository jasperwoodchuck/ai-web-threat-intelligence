import { EmptyState } from "../ui/EmptyState";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Badge as Pill } from "../ui/Badge";
import type { MessageAnalysisResponse, UrlAnalysisResponse } from "../../types/investigation";
import { ValueList } from "./ResultPrimitives";
import { UrlInvestigationReport } from "./UrlInvestigationReport";
import { toneForRisk } from "../../lib/analysis";

type InvestigationResultsProps = {
  result: UrlAnalysisResponse | null;
  messageResult: MessageAnalysisResponse | null;
  error: string;
  loading: boolean;
  detailedOpen: boolean;
  setDetailedOpen: (open: boolean) => void;
  riskEvidenceOpen: boolean;
  setRiskEvidenceOpen: (open: boolean) => void;
};

export function InvestigationResults({ result, messageResult, error, loading, detailedOpen, setDetailedOpen, riskEvidenceOpen, setRiskEvidenceOpen }: InvestigationResultsProps) {

  return <>
        {error && <ErrorState message={error} />}

        {loading && <LoadingState />}

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

        {!result && !messageResult && !loading && !error && <EmptyState />}

        {result && <UrlInvestigationReport result={result} detailedOpen={detailedOpen} setDetailedOpen={setDetailedOpen} riskEvidenceOpen={riskEvidenceOpen} setRiskEvidenceOpen={setRiskEvidenceOpen} />}
  </>;
}


