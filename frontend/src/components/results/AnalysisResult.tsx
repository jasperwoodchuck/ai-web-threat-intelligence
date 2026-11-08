import { useCallback, useState, type ReactNode } from "react";
import { Badge } from "../ui/Badge";
import type {
  FileAnalysisResponse,
  AIExplanation,
  MessageAnalysisResponse,
  NormalizedAnalysisResult,
  SummaryFinding,
  Tone,
  UrlAnalysisResponse,
} from "../../types/investigation";
import { httpStatusText, keyFindings, toneForRisk } from "../../lib/analysis";
import { DetailPanel, EvidenceList, KeyValueGrid, ValueList } from "./ResultPrimitives";
import { AnalysisDetailModal, type AnalysisCardDetail } from "./AnalysisDetailModal";
import { ReportExportActions } from "./ReportExportActions";
import type { AnalysisApiResult } from "../../lib/reportExport";
import { getTyposquattingDetection } from "../../lib/typosquatting";
import {
  TyposquattingDetectionCard,
} from "./TyposquattingDetectionCard";

const MIN_CLASSIFICATION_CONFIDENCE = 0.6;

function toneForIndicator(severity: string): Tone {
  if (["critical", "high"].includes(severity.toLowerCase())) return "danger";
  if (severity.toLowerCase() === "medium") return "warning";
  return "info";
}

function hasAdditionalDetails(data: unknown): boolean {
  if (data === null || data === undefined) return false;
  if (typeof data === "string") return data.trim().length > 0;
  if (Array.isArray(data)) return data.some(hasAdditionalDetails);
  if (typeof data === "object") return Object.values(data).some(hasAdditionalDetails);
  return true;
}

function aiStatusLabel(overview: AIExplanation): string {
  return {
    available: "Available",
    unavailable: "Unavailable",
    malformed: "Malformed",
    not_requested: "Not requested",
  }[overview.status];
}

function aiStatusTone(overview: AIExplanation): Tone {
  if (overview.status === "available") return "info";
  return overview.status === "not_requested" ? "neutral" : "warning";
}

function hasAIAdditionalDetails(overview: AIExplanation): boolean {
  return Boolean(
    overview.summary?.trim() ||
      overview.suspicious_indicators.length ||
      overview.evidence.length ||
      overview.recommended_actions.length ||
      overview.limitations.length ||
      overview.confidence !== null ||
      overview.advisory_note.trim(),
  );
}

function unavailableAiOverview(note: string): AIExplanation {
  return {
    status: "unavailable",
    summary: null,
    suspicious_indicators: [],
    evidence: [],
    recommended_actions: [],
    limitations: [],
    confidence: null,
    advisory_note: note,
  };
}

function normalizeUrl(result: UrlAnalysisResponse): NormalizedAnalysisResult {
  const findings = keyFindings(result);
  const status = result.http_analysis.status_code;
  return {
    aiOverview:
      result.ai_explanation ??
      unavailableAiOverview(
        "The backend did not provide an AI overview for this website analysis.",
      ),
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
        details: result.dns_analysis,
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
        details: result.tls_analysis,
        tone: result.tls_analysis.certificate_verified ? "good" : "neutral",
      },
      {
        title: "HTTP",
        state: result.http_analysis.request_successful ? "Received" : "Unavailable",
        detail:
          status === null ? "Response metadata" : `HTTP ${status} ${httpStatusText(status)}`.trim(),
        details: result.http_analysis,
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
        details: {
          threat_intelligence: result.threat_intelligence,
          phishing_analysis: result.phishing_analysis,
          typosquatting: result.typosquatting,
        },
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
        details: result.phishing_analysis,
        tone: result.phishing_analysis.is_suspicious ? "warning" : "good",
      },
    ],
  };
}

function normalizeMessage(result: MessageAnalysisResponse): NormalizedAnalysisResult {
  const findings: SummaryFinding[] = result.deterministic_indicators.map((item) => ({
    title: item.description,
    detail: item.evidence,
    details: item,
    tone: toneForIndicator(item.severity),
  }));
  for (const item of result.url_threat_intelligence) {
    if (item.status === "matched")
      findings.push({
        title: "Threat intelligence match",
        detail: `${item.source} matched ${item.indicator}.`,
        details: item,
        tone: "danger",
      });
  }
  for (const item of result.ai_explanation.suspicious_indicators)
    findings.push({
      title: item,
      detail: "Advisory AI observation; review the supporting evidence.",
      details: result.ai_explanation,
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
    aiOverview: result.ai_explanation,
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
        details: {
          extracted_urls: result.extracted_urls,
          url_threat_intelligence: result.url_threat_intelligence,
          extracted_email_addresses: result.extracted_email_addresses,
          extracted_phone_numbers: result.extracted_phone_numbers,
        },
        tone: result.extracted_urls.length ? "warning" : "neutral",
      },
      {
        title: "Urgency",
        state: result.deterministic_indicators.some((item) => item.category === "urgency")
          ? "Detected"
          : "No signal",
        detail: "Deterministic text check",
        details: result.deterministic_indicators.filter((item) => item.category === "urgency"),
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
        details: result.deterministic_indicators.filter((item) => item.category === "impersonation"),
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
        details: result.deterministic_indicators.filter(
          (item) => item.category === "attachment_reference",
        ),
        tone: result.deterministic_indicators.some(
          (item) => item.category === "attachment_reference",
        )
          ? "warning"
          : "neutral",
      },
      {
        title: "AI interpretation",
        state: aiStatusLabel(result.ai_explanation),
        detail: "Advisory",
        details: hasAIAdditionalDetails(result.ai_explanation) ? result.ai_explanation : undefined,
        tone: aiStatusTone(result.ai_explanation),
      },
    ],
  };
}

function normalizeFile(result: FileAnalysisResponse): NormalizedAnalysisResult {
  return {
    aiOverview: result.ai_explanation,
    contentType:
      result.classification_confidence < MIN_CLASSIFICATION_CONFIDENCE
        ? "Unknown"
        : result.content_type
            .replaceAll("_", " ")
            .replace(/\b\w/g, (letter) => letter.toUpperCase()),
    risk: result.risk_assessment,
    findings: result.key_findings.slice(0, 4).map((item) => ({
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
        details: {
          content_type: result.content_type,
          classification_confidence: result.classification_confidence,
          classification_reasoning: result.classification_reasoning,
        },
        tone: result.classification_confidence < MIN_CLASSIFICATION_CONFIDENCE ? "neutral" : "info",
      },
      {
        title: "Text extraction",
        state: result.extracted_text ? "Text found" : "No text",
        detail: result.media_type.startsWith("image/") ? "OCR" : "Document extraction",
        details: result.extracted_text || undefined,
        tone: result.extracted_text ? "good" : "neutral",
      },
      {
        title: "Links",
        state: result.extracted_urls.length
          ? `${result.extracted_urls.length} found`
          : "None found",
        detail: "Reputation lookup in details",
        details: hasAdditionalDetails({
          extracted_urls: result.extracted_urls,
          url_threat_intelligence: result.url_threat_intelligence,
        })
          ? {
              extracted_urls: result.extracted_urls,
              url_threat_intelligence: result.url_threat_intelligence,
            }
          : undefined,
        tone: result.extracted_urls.length ? "warning" : "neutral",
      },
      {
        title: "AI interpretation",
        state: aiStatusLabel(result.ai_explanation),
        detail: "Advisory",
        details: hasAIAdditionalDetails(result.ai_explanation) ? result.ai_explanation : undefined,
        tone: aiStatusTone(result.ai_explanation),
      },
    ],
  };
}

function AiOverviewCard({ overview }: { overview: AIExplanation }) {
  const [detail, setDetail] = useState<AnalysisCardDetail | null>(null);
  const available = overview.status === "available";
  const statusLabel = {
    available: "Available",
    unavailable: "Unavailable",
    malformed: "Malformed",
    not_requested: "Not requested",
  }[overview.status];
  const preview = available
    ? overview.summary || "No AI overview was returned."
    : overview.status === "malformed"
      ? "OpenRouter returned output that did not match the expected schema. See AI details for the validation reason."
      : overview.status === "not_requested"
        ? "AI interpretation was not requested for this content."
        : overview.limitations.some((item) => /rate limit|HTTP 429/i.test(item))
          ? "AI overview is temporarily unavailable because the provider is rate limited. Review the deterministic analysis below."
        : overview.limitations.some((item) => /image analysis|image OCR/i.test(item))
          ? "Image analysis is unavailable. Review the available security checks and evidence."
          : "AI interpretation is unavailable. Review the security checks and evidence.";
  const detailsAvailable = hasAIAdditionalDetails(overview);
  const content = (
    <div className="ai-overview-expanded">
      <p>{overview.advisory_note}</p>
      {overview.summary && <p>{overview.summary}</p>}
      {overview.confidence !== null && <p>Model confidence: {Math.round(overview.confidence * 100)}%</p>}
      {overview.suspicious_indicators.length > 0 && (
        <>
          <h4>Observed indicators</h4>
          <ValueList items={overview.suspicious_indicators} />
        </>
      )}
      {overview.evidence.length > 0 && (
        <>
          <h4>Supporting evidence</h4>
          <ValueList items={overview.evidence} />
        </>
      )}
      {overview.recommended_actions.length > 0 && (
        <>
          <h4>Suggested actions</h4>
          <ValueList items={overview.recommended_actions} />
        </>
      )}
      {overview.limitations.length > 0 && (
        <>
          <h4>Limitations</h4>
          <ValueList items={overview.limitations} />
        </>
      )}
    </div>
  );

  const overviewContent = (
    <>
        <span className="ai-overview-card-heading">
          <span className="ai-advisory-mark" aria-hidden="true">
            ✦
          </span>
          <span>
            <strong>AI overview</strong>
            <small>Advisory interpretation</small>
          </span>
          <Badge tone={available ? "info" : overview.status === "not_requested" ? "neutral" : "warning"}>
            {statusLabel}
          </Badge>
          {detailsAvailable && (
            <span className="analysis-expand-icon" aria-hidden="true" title="Open AI details">
              ↗
            </span>
          )}
        </span>
        <span className="ai-overview-preview">{preview}</span>
    </>
  );

  return (
    <>
      {detailsAvailable ? (
        <button
          className="ai-overview-card ai-overview-trigger"
          type="button"
          aria-haspopup="dialog"
          aria-label={`AI overview: ${statusLabel}. Open interpretation details.`}
          onClick={() => setDetail({ title: "AI interpretation", status: statusLabel, data: overview, content })}
        >
          {overviewContent}
        </button>
      ) : (
        <div className="ai-overview-card">{overviewContent}</div>
      )}
      {detail && <AnalysisDetailModal detail={detail} onClose={() => setDetail(null)} />}
    </>
  );
}

function SecurityCheckCard({
  check,
  onOpen,
}: {
  check: NormalizedAnalysisResult["checks"][number];
  onOpen: (detail: AnalysisCardDetail) => void;
}) {
  const detailsAvailable = hasAdditionalDetails(check.details);
  const content = (
    <>
      <span className="overview-card-top">
        <span className="overview-title">{check.title}</span>
        {detailsAvailable && (
          <span className="analysis-expand-icon" aria-hidden="true" title="Open details">
            ↗
          </span>
        )}
      </span>
      <Badge tone={check.tone}>{check.state}</Badge>
      <strong className="overview-metric">{check.detail}</strong>
    </>
  );

  if (!detailsAvailable) return <div className="overview-card">{content}</div>;

  return (
    <button
      className="overview-card overview-card-interactive"
      type="button"
      aria-haspopup="dialog"
      aria-label={`${check.title}: ${check.state}. View analysis details.`}
      onClick={() => onOpen({ title: check.title, status: check.state, data: check.details })}
    >
      {content}
    </button>
  );
}

function FindingCard({
  finding,
  onOpen,
}: {
  finding: SummaryFinding;
  onOpen: (detail: AnalysisCardDetail) => void;
}) {
  const detailsAvailable = hasAdditionalDetails(finding.details);
  const content = (
    <>
      <span className={`key-finding-mark mark-${finding.tone}`} aria-hidden="true">
        {finding.tone === "good"
          ? "✓"
          : finding.tone === "danger" || finding.tone === "warning"
            ? "!"
            : "·"}
      </span>
      <span className="key-finding-copy">
        <strong>{finding.title}</strong>
        <span>{finding.detail}</span>
      </span>
      {detailsAvailable && (
        <span className="analysis-expand-icon" aria-hidden="true" title="Open evidence">
          ↗
        </span>
      )}
    </>
  );

  return (
    <li>
      {detailsAvailable ? (
        <button
          className="key-finding key-finding-interactive"
          type="button"
          aria-haspopup="dialog"
          aria-label={`${finding.title}. View supporting evidence.`}
          onClick={() => onOpen({ title: finding.title, status: "Finding", data: finding.details })}
        >
          {content}
        </button>
      ) : (
        <div className="key-finding">{content}</div>
      )}
    </li>
  );
}

function Summary({ result, source }: { result: NormalizedAnalysisResult; source: AnalysisApiResult }) {
  const [selectedCheck, setSelectedCheck] = useState<AnalysisCardDetail | null>(null);
  const closeDetail = useCallback(() => setSelectedCheck(null), []);
  const openDetail = (detail: AnalysisCardDetail) => setSelectedCheck(detail);
  const openRiskDetails = () =>
    openDetail({ title: "Risk assessment", status: result.risk.classification, data: result.risk });
  const riskTone = toneForRisk(result.risk.classification);
  const typosquatting = getTyposquattingDetection(source);
  return (
    <>
      <div className="report-heading">
        <p className="eyebrow">INVESTIGATION RESULTS</p>
        <ReportExportActions result={source} />
      </div>
      {result.contentType && (
        <div className="content-type-label">
          Content type <Badge tone="info">{result.contentType}</Badge>
        </div>
      )}
      <section
        className={`risk-hero risk-${riskTone} risk-hero-interactive`}
        role="button"
        tabIndex={0}
        aria-haspopup="dialog"
        aria-label={`Overall verdict: ${result.risk.classification}. Open risk assessment details.`}
        onClick={openRiskDetails}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openRiskDetails();
          }
        }}
      >
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
            <span className="analysis-expand-icon" aria-hidden="true" title="Open risk details">
              ↗
            </span>
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
      {typosquatting && <TyposquattingDetectionCard detection={typosquatting} />}
      <AiOverviewCard overview={result.aiOverview} />
      <section className="summary-findings">
        <div className="summary-section-heading">
          <div>
            <p className="eyebrow">PRIORITY EVIDENCE</p>
            <h3>Key findings</h3>
          </div>
        </div>
        <ul className="key-findings-list">
          {result.findings.slice(0, 4).map((item, index) => (
            <FindingCard finding={item} key={`${item.title}-${index}`} onOpen={openDetail} />
          ))}
        </ul>
      </section>
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
            <SecurityCheckCard check={check} key={check.title} onOpen={openDetail} />
          ))}
        </div>
      </section>
      {selectedCheck && <AnalysisDetailModal detail={selectedCheck} onClose={closeDetail} />}
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
            { label: "Scheme", value: result.http_analysis.scheme },
            { label: "Hostname", value: result.http_analysis.hostname },
            { label: "Request method", value: result.http_analysis.request_method },
            { label: "Response headers size", value: result.http_analysis.headers_size_bytes },
            { label: "Redirect detected", value: result.http_analysis.redirect_detected },
            { label: "Redirect status", value: result.http_analysis.redirect_status_code },
            { label: "Redirect destination", value: result.http_analysis.redirect_location },
            { label: "Final behavior", value: result.http_analysis.final_behavior },
            { label: "Error", value: result.http_analysis.error },
          ]}
        />
        <h4>HTTP and security headers</h4>
        <KeyValueGrid
          rows={Object.entries(result.http_analysis.security_headers).map(([label, value]) => ({
            label,
            value,
            mono: true,
          }))}
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
            { label: "Detected domain", value: result.typosquatting.domain },
            { label: "Reference domain", value: result.typosquatting.reference_domain },
            { label: "Technique", value: result.typosquatting.technique },
            { label: "Similarity", value: result.typosquatting.similarity },
            { label: "Evidence", value: result.typosquatting.evidence },
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
        detailsAvailable={result.risk_assessment.contributing_indicators.length > 0 || result.risk_assessment.limitations.length > 0}
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
        detailsAvailable={
          result.extracted_urls.length > 0 ||
          result.extracted_email_addresses.length > 0 ||
          result.extracted_phone_numbers.length > 0 ||
          result.url_threat_intelligence.length > 0
        }
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
        detailsAvailable={result.deterministic_indicators.length > 0}
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
        detailsAvailable={
          result.risk_assessment.contributing_indicators.length > 0 ||
          result.risk_assessment.limitations.length > 0
        }
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
        detailsAvailable={result.extracted_text.length > 0}
      >
        <pre className="ocr-output">{result.extracted_text || "No text was extracted."}</pre>
      </DetailPanel>
      <DetailPanel
        title="Extracted links and deterministic checks"
        status={`${result.extracted_urls.length} links`}
        summary="Message-pattern signals"
        detailsAvailable={
          result.extracted_urls.length > 0 ||
          result.deterministic_indicators.length > 0 ||
          result.url_threat_intelligence.length > 0
        }
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
        detailsAvailable={
          result.risk_assessment.contributing_indicators.length > 0 ||
          result.ai_explanation.recommended_actions.length > 0 ||
          result.risk_assessment.limitations.length > 0
        }
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
      <Summary result={normalized} source={result} />
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
