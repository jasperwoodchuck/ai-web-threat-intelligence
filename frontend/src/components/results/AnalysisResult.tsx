import type { ReactNode } from "react";
import { Badge } from "../ui/Badge";
import type {
  FileAnalysisResponse,
  MessageAnalysisResponse,
  NormalizedAnalysisResult,
  SummaryFinding,
  Tone,
  UrlAnalysisResponse,
} from "../../types/investigation";
import { httpStatusText, keyFindings, toneForRisk } from "../../lib/analysis";
import { DetailPanel, EvidenceList, KeyValueGrid, ValueList } from "./ResultPrimitives";

const MIN_CLASSIFICATION_CONFIDENCE = 0.6;

function toneForIndicator(severity: string): Tone {
  if (["critical", "high"].includes(severity.toLowerCase())) return "danger";
  if (severity.toLowerCase() === "medium") return "warning";
  return "info";
}

function normalizeUrl(result: UrlAnalysisResponse): NormalizedAnalysisResult {
  const findings = keyFindings(result);
  const status = result.http_analysis.status_code;
  return {
    risk: result.risk_assessment,
    findings,
    recommendation:
      result.risk_assessment.recommended_precautions[0] ??
      "Treat the URL as unverified and review the available evidence.",
    checks: [
      {
        title: "DNS",
        state: result.dns_analysis.resolution_succeeded ? "Resolved" : "Unavailable",
        detail: `${result.dns_analysis.ipv4_addresses.length + result.dns_analysis.ipv6_addresses.length} address records`,
        tone: result.dns_analysis.resolution_succeeded ? "good" : "warning",
      },
      {
        title: "TLS",
        state: result.tls_analysis.certificate_verified
          ? "Verified"
          : result.tls_analysis.status === "not_applicable"
            ? "Not used"
            : "Unavailable",
        detail: result.tls_analysis.protocol_version ?? "Certificate check",
        tone: result.tls_analysis.certificate_verified ? "good" : "neutral",
      },
      {
        title: "HTTP",
        state: result.http_analysis.request_successful ? "Received" : "Unavailable",
        detail:
          status === null ? "Response metadata" : `HTTP ${status} ${httpStatusText(status)}`.trim(),
        tone: result.http_analysis.request_successful ? "good" : "warning",
      },
      {
        title: "Reputation",
        state:
          result.threat_intelligence.status === "matched"
            ? "Match"
            : result.threat_intelligence.status === "no_match"
              ? "No match"
              : "Unavailable",
        detail: result.threat_intelligence.source,
        tone:
          result.threat_intelligence.status === "matched"
            ? "danger"
            : result.threat_intelligence.status === "no_match"
              ? "good"
              : "warning",
      },
      {
        title: "Phishing signals",
        state: result.phishing_analysis.is_suspicious ? "Signals found" : "No signal",
        detail: `${result.phishing_analysis.indicators.length} indicators`,
        tone: result.phishing_analysis.is_suspicious ? "warning" : "good",
      },
    ],
  };
}

function normalizeMessage(result: MessageAnalysisResponse): NormalizedAnalysisResult {
  const findings: SummaryFinding[] = result.deterministic_indicators.map((item) => ({
    title: item.description,
    detail: item.evidence,
    tone: toneForIndicator(item.severity),
  }));
  for (const item of result.url_threat_intelligence) {
    if (item.status === "matched")
      findings.push({
        title: "Threat intelligence match",
        detail: `${item.source} matched ${item.indicator}.`,
        tone: "danger",
      });
  }
  for (const item of result.ai_explanation.suspicious_indicators)
    findings.push({
      title: item,
      detail: "Advisory AI observation; review the supporting evidence.",
      tone: "info",
    });
  const unique = findings
    .filter((item, index) => findings.findIndex((other) => other.title === item.title) === index)
    .slice(0, 4);
  if (!unique.length)
    unique.push({
      title: "No listed indicators detected",
      detail: "This does not establish that the message is safe.",
      tone: "neutral",
    });
  return {
    aiOverview: {
      status: result.ai_explanation.status,
      summary: result.ai_explanation.summary,
      advisoryNote: result.ai_explanation.advisory_note,
    },
    risk: result.risk_assessment,
    findings: unique,
    recommendation:
      result.ai_explanation.recommended_actions[0] ??
      result.risk_assessment.recommended_precautions[0] ??
      "Verify the sender and any links independently.",
    checks: [
      {
        title: "Links",
        state: result.extracted_urls.length
          ? `${result.extracted_urls.length} found`
          : "None found",
        detail: "URLs are checked against reputation data only",
        tone: result.extracted_urls.length ? "warning" : "neutral",
      },
      {
        title: "Urgency",
        state: result.deterministic_indicators.some((item) => item.category === "urgency")
          ? "Detected"
          : "No signal",
        detail: "Deterministic text check",
        tone: result.deterministic_indicators.some((item) => item.category === "urgency")
          ? "warning"
          : "good",
      },
      {
        title: "Impersonation",
        state: result.deterministic_indicators.some((item) => item.category === "impersonation")
          ? "Possible"
          : "No signal",
        detail: "Claim not independently verified",
        tone: result.deterministic_indicators.some((item) => item.category === "impersonation")
          ? "warning"
          : "good",
      },
      {
        title: "Attachment reference",
        state: result.deterministic_indicators.some(
          (item) => item.category === "attachment_reference",
        )
          ? "Mentioned"
          : "None detected",
        detail: "Attachment contents are not provided in text mode",
        tone: result.deterministic_indicators.some(
          (item) => item.category === "attachment_reference",
        )
          ? "warning"
          : "neutral",
      },
      {
        title: "AI interpretation",
        state: result.ai_explanation.status === "available" ? "Available" : "Unavailable",
        detail: "Advisory",
        tone: result.ai_explanation.status === "available" ? "info" : "warning",
      },
    ],
  };
}

function normalizeFile(result: FileAnalysisResponse): NormalizedAnalysisResult {
  return {
    aiOverview: {
      status: result.ai_explanation.status,
      summary: result.ai_explanation.summary ?? result.summary,
      advisoryNote: result.ai_explanation.advisory_note,
    },
    contentType:
      result.classification_confidence < MIN_CLASSIFICATION_CONFIDENCE
        ? "Unknown"
        : result.content_type
            .replaceAll("_", " ")
            .replace(/\b\w/g, (letter) => letter.toUpperCase()),
    risk: result.risk_assessment,
    findings: result.key_findings
      .slice(0, 4)
      .map((item) => ({
        title: item,
        detail: "Evidence from extracted content or visual inspection.",
        tone: /match|credential|urgent|impersonat|payment|suspicious/i.test(item)
          ? "warning"
          : "info",
      })),
    recommendation: result.recommended_action,
    checks: [
      {
        title: "Content type",
        state:
          result.classification_confidence < MIN_CLASSIFICATION_CONFIDENCE
            ? "Unknown"
            : result.content_type.replaceAll("_", " "),
        detail: `${Math.round(result.classification_confidence * 100)}% classification confidence`,
        tone: result.classification_confidence < MIN_CLASSIFICATION_CONFIDENCE ? "neutral" : "info",
      },
      {
        title: "Text extraction",
        state: result.extracted_text ? "Text found" : "No text",
        detail: result.media_type.startsWith("image/") ? "OCR" : "Document extraction",
        tone: result.extracted_text ? "good" : "neutral",
      },
      {
        title: "Links",
        state: result.extracted_urls.length
          ? `${result.extracted_urls.length} found`
          : "None found",
        detail: "Reputation lookup in details",
        tone: result.extracted_urls.length ? "warning" : "neutral",
      },
      {
        title: "AI interpretation",
        state: result.ai_explanation.status === "available" ? "Available" : "Unavailable",
        detail: "Advisory",
        tone: result.ai_explanation.status === "available" ? "info" : "warning",
      },
    ],
  };
}

function Summary({ result }: { result: NormalizedAnalysisResult }) {
  const riskTone = toneForRisk(result.risk.classification);
  return (
    <>
      <div className="report-heading">
        <p className="eyebrow">INVESTIGATION RESULTS</p>
      </div>
      {result.contentType && (
        <div className="content-type-label">
          Content type <Badge tone="info">{result.contentType}</Badge>
        </div>
      )}
      <section className={`risk-hero risk-${riskTone}`} aria-label="Overall risk summary">
        <div className="risk-main">
          <div className="risk-heading">
            <div className="section-icon risk-icon" aria-hidden="true">
              !
            </div>
            <div>
              <p className="eyebrow">OVERALL VERDICT</p>
              <h2>{result.risk.classification}</h2>
            </div>
            <Badge tone={riskTone}>{result.risk.classification}</Badge>
          </div>
          <div className="risk-meter-wrap">
            <div className="risk-meter-label">
              <span>Risk score</span>
              <span>
                {result.risk.score} <small>/ 100</small>
              </span>
            </div>
            <progress
              className={`risk-meter meter-${riskTone}`}
              max="100"
              value={result.risk.score}
              aria-label={`Risk score ${result.risk.score} out of 100`}
            />
          </div>
        </div>
        <div className="risk-side-metrics">
          <div className="risk-stat">
            <span className="stat-label">Confidence</span>
            <strong>
              {Math.round(result.risk.confidence * 100)}
              <small>%</small>
            </strong>
          </div>
          <div className="risk-stat">
            <span className="stat-label">Signals</span>
            <strong>{result.risk.contributing_indicators.length}</strong>
          </div>
        </div>
      </section>
      <section className="summary-findings">
        <div className="summary-section-heading">
          <div>
            <p className="eyebrow">PRIORITY EVIDENCE</p>
            <h3>Key findings</h3>
          </div>
        </div>
        <ul className="key-findings-list">
          {result.findings.slice(0, 4).map((item, index) => (
            <li className="key-finding" key={`${item.title}-${index}`}>
              <span className={`key-finding-mark mark-${item.tone}`} aria-hidden="true">
                {item.tone === "good"
                  ? "✓"
                  : item.tone === "danger" || item.tone === "warning"
                    ? "!"
                    : "·"}
              </span>
              <span className="key-finding-copy">
                <strong>{item.title}</strong>
                <span>{item.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      </section>
      {result.aiOverview && (
        <section className="result-section ai-advisory ai-overview" aria-label="AI overview">
          <div className="ai-advisory-heading">
            <span className="ai-advisory-mark" aria-hidden="true">✦</span>
            <div>
              <h3>AI overview</h3>
              <span>Advisory interpretation</span>
            </div>
            <Badge tone={result.aiOverview.status === "available" ? "info" : "warning"}>
              {result.aiOverview.status === "available" ? "Available" : "Unavailable"}
            </Badge>
          </div>
          <p>
            {result.aiOverview.status === "available"
              ? result.aiOverview.summary || "No AI overview was returned."
              : "An AI overview could not be generated for this analysis. Review the deterministic checks and evidence below."}
          </p>
          <p className="ai-overview-note">{result.aiOverview.advisoryNote}</p>
        </section>
      )}
      <section className="notice-card notice-precautions analysis-recommendation">
        <div className="notice-heading">
          <span aria-hidden="true">✓</span>
          <h3>Recommended action</h3>
        </div>
        <p>{result.recommendation}</p>
      </section>
      <section className="summary-overview">
        <div className="summary-section-heading">
          <div>
            <p className="eyebrow">AT A GLANCE</p>
            <h3>Security checks</h3>
          </div>
        </div>
        <div className="overview-grid">
          {result.checks.map((check) => (
            <div className="overview-card" key={check.title}>
              <div className="overview-card-top">
                <span className="overview-title">{check.title}</span>
              </div>
              <Badge tone={check.tone}>{check.state}</Badge>
              <strong className="overview-metric">{check.detail}</strong>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function UrlDetails({ result }: { result: UrlAnalysisResponse }) {
  const dnsRecords: Array<[string, string[]]> = [
    ["A records", result.dns_analysis.ipv4_addresses],
    ["AAAA records", result.dns_analysis.ipv6_addresses],
    ["Nameservers", result.dns_analysis.nameservers],
    ["TXT records", result.dns_analysis.txt_records],
  ];
  return (
    <section className="analysis-grid" aria-label="Website technical evidence">
      <DetailPanel
        title="URL structure"
        status={result.url_analysis.is_valid ? "ok" : "error"}
        summary={result.url_analysis.normalized_url ?? "URL details"}
      >
        <KeyValueGrid
          rows={Object.entries(result.url_analysis).map(([label, value]) => ({
            label: label.replaceAll("_", " "),
            value,
            mono: ["original_url", "normalized_url", "hostname", "path"].includes(label),
          }))}
        />
      </DetailPanel>
      <DetailPanel
        title="DNS records"
        status={result.dns_analysis.status}
        summary={`${result.dns_analysis.ipv4_addresses.length} A · ${result.dns_analysis.ipv6_addresses.length} AAAA records`}
      >
        <KeyValueGrid
          rows={[
            { label: "Hostname", value: result.dns_analysis.hostname },
            { label: "Resolution", value: result.dns_analysis.resolution_succeeded },
            { label: "CNAME", value: result.dns_analysis.cname_target },
            { label: "Reason", value: result.dns_analysis.reason },
          ]}
        />
        {dnsRecords.map(([label, values]) => (
          <div key={label}>
            <h4>{label}</h4>
            <ValueList items={values} />
          </div>
        ))}
        <EvidenceList
          items={result.risk_assessment.contributing_indicators.filter(
            (item) => item.source === "dns_analysis",
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="TLS certificate"
        status={result.tls_analysis.status}
        summary={result.tls_analysis.protocol_version ?? "Certificate diagnostics"}
      >
        <KeyValueGrid
          rows={[
            { label: "Verified", value: result.tls_analysis.certificate_verified },
            { label: "Hostname", value: result.tls_analysis.hostname },
            { label: "Certificate", value: result.tls_analysis.certificate?.subject },
            { label: "Issuer", value: result.tls_analysis.certificate?.issuer },
            { label: "Expires", value: result.tls_analysis.certificate?.not_after },
          ]}
        />
        <EvidenceList
          items={result.risk_assessment.contributing_indicators.filter(
            (item) => item.source === "tls_analysis",
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="HTTP and redirects"
        status={result.http_analysis.status}
        summary={
          result.http_analysis.status_code === null
            ? "Response diagnostics"
            : `HTTP ${result.http_analysis.status_code}`
        }
      >
        <KeyValueGrid
          rows={[
            { label: "Request successful", value: result.http_analysis.request_successful },
            { label: "Redirect detected", value: result.http_analysis.redirect_detected },
            { label: "Redirect status", value: result.http_analysis.redirect_status_code },
            { label: "Redirect destination", value: result.http_analysis.redirect_location },
            { label: "Final behavior", value: result.http_analysis.final_behavior },
            { label: "Error", value: result.http_analysis.error },
          ]}
        />
        <EvidenceList
          items={result.risk_assessment.contributing_indicators.filter(
            (item) => item.source === "http_analysis",
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="Phishing and reputation"
        status={result.threat_intelligence.status}
        summary={`${result.phishing_analysis.indicators.length} URL indicators`}
      >
        <KeyValueGrid
          rows={[
            { label: "Provider", value: result.threat_intelligence.source },
            { label: "Status", value: result.threat_intelligence.status },
            { label: "Indicator", value: result.threat_intelligence.indicator },
            { label: "Threat type", value: result.threat_intelligence.threat_type },
            { label: "Typosquatting", value: result.typosquatting.detected },
            { label: "Possible intended site", value: result.typosquatting.possible_intended_site },
          ]}
        />
        <EvidenceList
          items={result.risk_assessment.contributing_indicators.filter((item) =>
            ["phishing_analysis", "threat_intelligence"].includes(item.source),
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="Risk evidence and limitations"
        status={`${result.risk_assessment.contributing_indicators.length} signals`}
        summary="Scoring inputs and caveats"
      >
        <EvidenceList items={result.risk_assessment.contributing_indicators} />
        <h4>Limitations</h4>
        <ValueList items={result.risk_assessment.limitations} />
      </DetailPanel>
    </section>
  );
}

function MessageDetails({ result }: { result: MessageAnalysisResponse }) {
  return (
    <section className="analysis-grid" aria-label="Message evidence">
      <DetailPanel
        title="Extracted links and contacts"
        status={`${result.extracted_urls.length} links`}
        summary="Detected entities"
      >
        <h4>Links</h4>
        <ValueList items={result.extracted_urls} />
        <h4>Email addresses</h4>
        <ValueList items={result.extracted_email_addresses} />
        <h4>Phone numbers</h4>
        <ValueList items={result.extracted_phone_numbers} />
        <h4>URL reputation</h4>
        <ValueList
          items={result.url_threat_intelligence.map(
            (item) => `${item.source}: ${item.status} · ${item.indicator}`,
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="Deterministic language checks"
        status={`${result.deterministic_indicators.length} signals`}
        summary="Rule-based observations"
      >
        <ul className="result-list">
          {result.deterministic_indicators.map((item, index) => (
            <li key={`${item.category}-${index}`}>
              <strong>{item.description}</strong>
              <span>{item.evidence}</span>
            </li>
          ))}
        </ul>
      </DetailPanel>
      <DetailPanel
        title="AI interpretation"
        status={result.ai_explanation.status}
        summary="Advisory model output"
      >
        <p>{result.ai_explanation.advisory_note}</p>
        <p>{result.ai_explanation.summary ?? "No interpretation returned."}</p>
        <h4>Suggested indicators</h4>
        <ValueList items={result.ai_explanation.suspicious_indicators} />
        <h4>Evidence</h4>
        <ValueList items={result.ai_explanation.evidence} />
        <h4>Recommended actions</h4>
        <ValueList items={result.ai_explanation.recommended_actions} />
        <h4>Limitations</h4>
        <ValueList items={result.ai_explanation.limitations} />
      </DetailPanel>
      <DetailPanel
        title="Risk evidence"
        status={`${result.risk_assessment.contributing_indicators.length} signals`}
        summary="Scoring inputs"
      >
        <EvidenceList items={result.risk_assessment.contributing_indicators} />
        <ValueList items={result.risk_assessment.limitations} />
      </DetailPanel>
    </section>
  );
}

function FileDetails({ result }: { result: FileAnalysisResponse }) {
  return (
    <section className="analysis-grid" aria-label="File evidence">
      <DetailPanel
        title="File metadata"
        status={result.media_type}
        summary={`${(result.size_bytes / 1024 / 1024).toFixed(2)} MB`}
      >
        <KeyValueGrid
          rows={[
            { label: "Filename", value: result.filename },
            { label: "MIME type", value: result.media_type },
            { label: "Size", value: `${result.size_bytes} bytes` },
            { label: "SHA-256", value: result.sha256, mono: true },
            { label: "Content type", value: result.content_type },
            {
              label: "Classification confidence",
              value: `${Math.round(result.classification_confidence * 100)}%`,
            },
            { label: "Classification reasoning", value: result.classification_reasoning },
          ]}
        />
      </DetailPanel>
      <DetailPanel
        title="OCR / extracted text"
        status={result.extracted_text ? "available" : "empty"}
        summary={`${result.extracted_text.length.toLocaleString()} characters`}
      >
        <pre className="ocr-output">{result.extracted_text || "No text was extracted."}</pre>
      </DetailPanel>
      <DetailPanel
        title="Extracted links and deterministic checks"
        status={`${result.extracted_urls.length} links`}
        summary="Message-pattern signals"
      >
        <h4>Links</h4>
        <ValueList items={result.extracted_urls} />
        <h4>Rule-based indicators</h4>
        <ul className="result-list">
          {result.deterministic_indicators.map((item, index) => (
            <li key={`${item.category}-${index}`}>
              <strong>{item.description}</strong>
              <span>{item.evidence}</span>
            </li>
          ))}
        </ul>
        <h4>URL reputation</h4>
        <ValueList
          items={result.url_threat_intelligence.map(
            (item) => `${item.source}: ${item.status} · ${item.indicator}`,
          )}
        />
      </DetailPanel>
      <DetailPanel
        title="Visual indicators and AI interpretation"
        status={result.ai_explanation.status}
        summary="Advisory model evidence"
      >
        <p>{result.ai_explanation.advisory_note}</p>
        <p>{result.ai_explanation.summary ?? result.summary}</p>
        <h4>Visual indicators</h4>
        <ValueList items={result.indicators} />
        <h4>Classification reasoning</h4>
        <p>{result.classification_reasoning || "No classification reasoning was returned."}</p>
        <h4>AI evidence</h4>
        <ValueList items={result.ai_explanation.evidence} />
        <h4>Limitations</h4>
        <ValueList items={result.limitations} />
      </DetailPanel>
      <DetailPanel
        title="Risk evidence and recommendations"
        status={`${result.risk_assessment.contributing_indicators.length} signals`}
        summary="Scoring inputs"
      >
        <EvidenceList items={result.risk_assessment.contributing_indicators} />
        <h4>Recommended actions</h4>
        <ValueList items={result.ai_explanation.recommended_actions} />
        <h4>Risk limitations</h4>
        <ValueList items={result.risk_assessment.limitations} />
      </DetailPanel>
    </section>
  );
}

export function AnalysisResult({
  result,
  detailedOpen,
  onDetailedToggle,
}: {
  result: UrlAnalysisResponse | MessageAnalysisResponse | FileAnalysisResponse;
  detailedOpen: boolean;
  onDetailedToggle: (open: boolean) => void;
}) {
  let normalized: NormalizedAnalysisResult;
  let detailContent: ReactNode;
  if ("url_analysis" in result) {
    normalized = normalizeUrl(result);
    detailContent = <UrlDetails result={result} />;
  } else if ("deterministic_indicators" in result && "filename" in result) {
    normalized = normalizeFile(result);
    detailContent = <FileDetails result={result} />;
  } else {
    normalized = normalizeMessage(result);
    detailContent = <MessageDetails result={result} />;
  }
  return (
    <section className="report unified-report" aria-live="polite">
      <Summary result={normalized} />
      <details
        className="technical-details"
        open={detailedOpen}
        onToggle={(event) => onDetailedToggle(event.currentTarget.open)}
      >
        <summary className="technical-summary">
          <span className="technical-summary-icon" aria-hidden="true">
            ⌄
          </span>
          <span className="technical-summary-copy">
            <strong>Detailed information</strong>
            <span>Supporting evidence, extracted content, and technical diagnostics</span>
          </span>
          <span className="technical-summary-action">
            {detailedOpen ? "Hide details" : "Show details"}
          </span>
        </summary>
        {detailContent}
      </details>
      <footer className="report-footer">
        Automated analysis provides evidence for review; it does not prove content is safe or
        malicious.
      </footer>
    </section>
  );
}
