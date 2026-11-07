import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import "./App.css";

type Tone = "neutral" | "good" | "warning" | "danger" | "info";
type Theme = "light" | "dark";

const THEME_STORAGE_KEY = "web-threat-intelligence-theme";

function getInitialTheme(): Theme {
  let theme: string | null = null;
  try {
    theme = typeof window === "undefined" ? null : window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Theme selection still works for this session when storage is unavailable.
  }

  if (theme === "light" || theme === "dark") return theme;
  return typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

interface UrlAnalysis {
  original_url: string;
  normalized_url: string | null;
  scheme: string | null;
  hostname: string | null;
  port: number | null;
  path: string | null;
  has_query: boolean;
  has_fragment: boolean;
  has_username: boolean;
  has_password: boolean;
  registered_domain: string | null;
  subdomain: string | null;
  public_suffix: string | null;
  is_ip_address: boolean;
  is_valid: boolean;
  validation_error: string | null;
}

interface DnsError {
  record_type: string;
  error_type: string;
  message: string;
}

interface DnsAnalysis {
  hostname: string;
  status: string;
  resolution_succeeded: boolean;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  cname_target: string | null;
  mail_servers: { preference: number; exchange: string }[];
  nameservers: string[];
  txt_records: string[];
  errors: DnsError[];
  reason: string | null;
}

interface PhishingIndicator {
  type: string;
  severity: string;
  description: string;
  evidence: string;
  score_contribution: number;
}

interface FraudUrlSignal {
  status: string;
  result: Record<string, unknown> | null;
  score_contribution: number;
  error: string | null;
}

interface PhishingAnalysis {
  is_suspicious: boolean;
  score: number;
  indicators: PhishingIndicator[];
  fraudurl: FraudUrlSignal;
}

interface TyposquattingAnalysis {
  detected: boolean;
  submitted_domain: string | null;
  possible_intended_site: string | null;
  similarity: number | null;
  edit_distance: number | null;
}

interface RiskEvidence {
  source: string;
  indicator: string;
  severity: string;
  weight: number;
  description: string;
  evidence: string;
}

interface RiskAssessment {
  classification: string;
  score: number;
  confidence: number;
  contributing_indicators: RiskEvidence[];
  recommended_precautions: string[];
  limitations: string[];
}

interface TlsCertificate {
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean | null;
  san_names: string[];
  hostname_matches: boolean | null;
  public_key_algorithm: string | null;
  public_key_size: number | null;
  signature_algorithm: string | null;
}

interface TlsFinding {
  type: string;
  severity: string;
  description: string;
  evidence: string;
}

interface TlsAnalysis {
  status: string;
  supported: boolean;
  connection_successful: boolean;
  hostname: string | null;
  port: number | null;
  protocol_version: string | null;
  certificate_verified: boolean | null;
  certificate: TlsCertificate | null;
  certificate_chain: { subject: string; issuer: string; serial_number: string }[];
  certificate_transparency: { status: string; reason: string };
  certificate_revocation: { status: string; reason: string };
  findings: TlsFinding[];
  trust_note: string;
}

interface HttpFinding {
  type: string;
  severity: string;
  description: string;
  evidence: string;
  score_contribution: number;
}

interface HttpAnalysis {
  status: string;
  supported: boolean;
  request_successful: boolean;
  scheme: string | null;
  hostname: string | null;
  port: number | null;
  request_method: string;
  status_code: number | null;
  security_headers: Record<string, string | null>;
  headers_size_bytes: number | null;
  redirect_detected: boolean;
  redirect_status_code: number | null;
  redirect_location: string | null;
  final_behavior: string;
  error: string | null;
  findings: HttpFinding[];
  trust_note: string;
}

interface ThreatIntelligenceResult {
  status: "matched" | "no_match" | "unavailable";
  matched: boolean | null;
  source: string;
  indicator: string;
  match_scope: string | null;
  threat_type: string | null;
  confidence: number | null;
  evidence: Record<string, unknown>;
  reference: string | null;
  checked_at: string;
  error: string | null;
}

interface UrlAnalysisResponse {
  url_analysis: UrlAnalysis;
  dns_analysis: DnsAnalysis;
  phishing_analysis: PhishingAnalysis;
  typosquatting: TyposquattingAnalysis;
  risk_assessment: RiskAssessment;
  tls_analysis: TlsAnalysis;
  http_analysis: HttpAnalysis;
  threat_intelligence: ThreatIntelligenceResult;
}

interface KeyValue {
  label: string;
  value: unknown;
  mono?: boolean;
}

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function toneForRisk(classification: string): Tone {
  if (classification === "Confirmed Malicious" || classification === "High Risk") return "danger";
  if (classification === "Suspicious") return "warning";
  if (classification === "Low Risk") return "good";
  return "neutral";
}

function statusTone(status: string): Tone {
  if (["matched", "error", "failed", "expired"].includes(status.toLowerCase())) return "danger";
  if (["warning", "suspicious"].includes(status.toLowerCase())) return "warning";
  if (["unavailable", "partial", "not_applicable", "not checked"].includes(status.toLowerCase())) {
    return "warning";
  }
  if (["ok", "no_match", "successful", "checked"].includes(status.toLowerCase())) return "good";
  return "neutral";
}

function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

function KeyValueGrid({ rows }: { rows: KeyValue[] }) {
  return (
    <dl className="key-value-grid">
      {rows.map((row) => (
        <div className="key-value" key={row.label}>
          <dt>{row.label}</dt>
          <dd className={row.mono ? "is-mono" : undefined}>{displayValue(row.value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function ValueList({ items, empty = "None reported" }: { items: string[]; empty?: string }) {
  if (items.length === 0) return <p className="empty-note">{empty}</p>;
  return (
    <ul className="compact-list">
      {items.map((item, index) => (
        <li className="value-chip is-mono" key={`${item}-${index}`}>
          {item}
        </li>
      ))}
    </ul>
  );
}

function DetailPanel({
  title,
  status,
  summary,
  children,
  className = "",
  id,
  open,
  onToggle,
}: {
  title: string;
  status: string;
  summary: string;
  children: ReactNode;
  className?: string;
  id?: string;
  open?: boolean;
  onToggle?: (open: boolean) => void;
}) {
  return (
    <details
      id={id}
      className={`detail-panel ${className}`}
      open={open}
      onToggle={onToggle ? (event) => onToggle(event.currentTarget.open) : undefined}
    >
      <summary>
        <span className="detail-title-block">
          <span className="detail-title">{title}</span>
          <span className="detail-summary">{summary}</span>
        </span>
        <Pill tone={statusTone(status)}>{status.replaceAll("_", " ")}</Pill>
      </summary>
      <div className="detail-content">{children}</div>
    </details>
  );
}

function OverviewCard({
  title,
  status,
  statusLabel,
  metric,
}: {
  title: string;
  status: string;
  statusLabel: string;
  metric: string;
}) {
  return (
    <div className="overview-card">
      <div className="overview-card-top">
        <span className="overview-title">{title}</span>
      </div>
      <Pill tone={statusTone(status)}>{statusLabel}</Pill>
      <strong className="overview-metric">{metric}</strong>
    </div>
  );
}

interface SummaryFinding {
  title: string;
  detail: string;
  tone: Tone;
}

function shortEvidenceTitle(item: RiskEvidence): string {
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

function shortEvidenceDescription(item: RiskEvidence): string {
  if (item.indicator === "fraudurl_probability") {
    const probability = /fraud_probability=([0-9]*\.?[0-9]+)/.exec(item.evidence)?.[1];
    if (probability !== undefined) {
      return `The URL detector estimated ${(Number(probability) * 100).toFixed(1)}% phishing probability.`;
    }
  }
  return item.description;
}

function keyFindings(result: UrlAnalysisResponse): SummaryFinding[] {
  const findings: SummaryFinding[] = [];
  const add = (finding: SummaryFinding) => {
    if (!findings.some((existing) => existing.title === finding.title)) findings.push(finding);
  };

  if (
    result.typosquatting.detected &&
    result.typosquatting.submitted_domain &&
    result.typosquatting.possible_intended_site
  ) {
    add({
      title: "Possible typosquatting",
      detail: `${result.typosquatting.submitted_domain} resembles ${result.typosquatting.possible_intended_site}.`,
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
        tone: "neutral",
      });
    } else if (tls.connection_successful && tls.certificate_verified === true) {
      add({
        title: "HTTPS transport",
        detail: `TLS connection and certificate verification succeeded${tls.protocol_version ? ` (${tls.protocol_version})` : ""}. This does not establish site legitimacy.`,
        tone: "good",
      });
    } else if (!tls.connection_successful) {
      add({
        title: "TLS check",
        detail: "The certificate connection could not be verified.",
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
      tone: http.request_successful ? "good" : "neutral",
    });
  }

  return findings.slice(0, 4);
}

function httpStatusText(status: number): string {
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

function EvidenceList({ items }: { items: RiskEvidence[] }) {
  if (items.length === 0) return <p className="empty-note">No evidence items were returned.</p>;
  return (
    <ol className="evidence-timeline">
      {items.map((item, index) => (
        <li className="evidence-item" key={`${item.source}-${item.indicator}-${index}`}>
          <span
            className={`evidence-node ${item.weight > 0 ? "node-risk" : item.weight < 0 ? "node-counter" : "node-neutral"}`}
            aria-hidden="true"
          />
          <div className="evidence-content">
            <div className="evidence-topline">
              <span className="evidence-source">{item.source.replaceAll("_", " ")}</span>
              <span
                className={`impact impact-${item.weight > 0 ? "risk" : item.weight < 0 ? "counter" : "neutral"}`}
              >
                {item.weight > 0 ? "+" : ""}
                {item.weight} impact
              </span>
            </div>
            <strong>{item.description}</strong>
            <p>{item.evidence}</p>
            <span className="evidence-meta">
              {item.indicator.replaceAll("_", " ")} · {item.severity} severity
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}

function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    const initialTheme = getInitialTheme();
    if (typeof document !== "undefined") {
      document.documentElement.dataset.theme = initialTheme;
      document.documentElement.style.colorScheme = initialTheme;
    }
    return initialTheme;
  });
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailedOpen, setDetailedOpen] = useState(false);
  const [riskEvidenceOpen, setRiskEvidenceOpen] = useState(false);

  async function handleAnalyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedUrl = url.trim();
    setError("");
    setResult(null);
    setDetailedOpen(false);
    setRiskEvidenceOpen(false);

    if (!submittedUrl) {
      setError("Enter a URL to analyze.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("/api/v1/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: submittedUrl }),
      });
      const payload: unknown = await response.json();

      if (!response.ok) {
        const detail =
          typeof payload === "object" && payload !== null && "detail" in payload
            ? payload.detail
            : null;
        setError(typeof detail === "string" ? detail : `Analysis failed (${response.status}).`);
        return;
      }

      setResult(payload as UrlAnalysisResponse);
    } catch {
      setError("Could not reach the analysis service.");
    } finally {
      setLoading(false);
    }
  }

  const risk = result?.risk_assessment;
  const riskTone = risk ? toneForRisk(risk.classification) : "neutral";
  const fraudResult = result ? result.phishing_analysis.fraudurl.result : null;
  const threat = result?.threat_intelligence;
  const typo = result?.typosquatting;
  const findings = result ? keyFindings(result) : [];
  const positiveSignalCount =
    risk?.contributing_indicators.filter((item) => item.weight > 0).length ?? 0;

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
  }, [theme]);

  function selectTheme(nextTheme: Theme) {
    setTheme(nextTheme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {
      // Keep the selected theme for the current session if storage is unavailable.
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Web Threat Intelligence home">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none">
              <path d="M12 2.8 20 6v5.7c0 4.6-3.2 7.8-8 9.5-4.8-1.7-8-4.9-8-9.5V6l8-3.2Z" />
              <path d="m8.5 12.1 2.2 2.2 4.9-5" />
            </svg>
          </span>
          <span>Web Threat Intelligence</span>
        </a>
        <div className="topbar-actions">
          <div className="topbar-meta">
            <span className="live-indicator" />
            URL investigation
          </div>
          <div className="theme-toggle" role="group" aria-label="Color theme">
            <button
              type="button"
              aria-pressed={theme === "light"}
              onClick={() => selectTheme("light")}
            >
              Light
            </button>
            <button
              type="button"
              aria-pressed={theme === "dark"}
              onClick={() => selectTheme("dark")}
            >
              Dark
            </button>
          </div>
        </div>
      </header>

      <main id="top" className="main-container">
        <section className="intro-row">
          <div>
            <p className="eyebrow">SECURITY ANALYSIS WORKSPACE</p>
            <h1>Website investigation</h1>
            <p className="intro-copy">
              Review domain signals, transport security, and threat intelligence in one report.
            </p>
          </div>
          <div className="privacy-note">
            <span className="privacy-icon" aria-hidden="true">
              ✓
            </span>
            <span>
              Passive checks
              <br />
              <strong>No page scripts executed</strong>
            </span>
          </div>
        </section>

        <form className="scan-form" onSubmit={handleAnalyze}>
          <label htmlFor="url-input">URL to analyze</label>
          <div className="scan-controls">
            <div className="url-field-wrap">
              <svg className="url-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="12" cy="12" r="9" />
                <path d="M3.5 12h17M12 3c2.2 2.4 3.3 5.4 3.3 9s-1.1 6.6-3.3 9c-2.2-2.4-3.3-5.4-3.3-9S9.8 5.4 12 3Z" />
              </svg>
              <input
                id="url-input"
                type="url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com"
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? <span className="spinner" /> : null}
              {loading ? "Analyzing" : "Analyze URL"}
              {!loading ? <span aria-hidden="true">→</span> : null}
            </button>
          </div>
          <div className="form-footnote">
            <span>HTTP and HTTPS URLs supported</span>
            <span>Analysis may take a few seconds</span>
          </div>
        </form>

        {error && (
          <div className="alert alert-danger" role="alert">
            <span className="alert-symbol">!</span>
            <div>
              <strong>Analysis could not be completed</strong>
              <p>{error}</p>
            </div>
          </div>
        )}

        {loading && (
          <div className="loading-card" role="status">
            <span className="spinner spinner-dark" />
            <span>Collecting analysis signals…</span>
          </div>
        )}

        {!result && !loading && !error && (
          <section className="empty-state">
            <span className="empty-state-icon" aria-hidden="true">
              ⌕
            </span>
            <h2>Ready to investigate</h2>
            <p>
              Submit a URL above to review its structure, DNS, certificate, and reputation signals.
            </p>
          </section>
        )}

        {result && risk && threat && typo && (
          <section className="report" aria-live="polite">
            <div className="report-heading">
              <div>
                <p className="eyebrow">INVESTIGATION REPORT</p>
                <h2>Analysis overview</h2>
              </div>
              <span className="report-target is-mono">
                {result.url_analysis.normalized_url ?? result.url_analysis.original_url}
              </span>
            </div>

            <section className={`risk-hero risk-${riskTone}`} aria-labelledby="risk-title">
              <div className="risk-main">
                <div className="risk-heading">
                  <div className="section-icon risk-icon" aria-hidden="true">
                    !
                  </div>
                  <div>
                    <p className="eyebrow">OVERALL RISK ASSESSMENT</p>
                    <h2 id="risk-title">{risk.classification}</h2>
                  </div>
                  <Pill tone={riskTone}>{risk.classification}</Pill>
                </div>
                <p className="risk-summary">
                  {risk.classification === "Confirmed Malicious"
                    ? "An exact threat-intelligence match and supporting signals identify this URL as a known threat."
                    : typo.detected && typo.submitted_domain && typo.possible_intended_site
                      ? `The domain ${typo.submitted_domain} resembles ${typo.possible_intended_site}, and the available signals place it in ${risk.classification}.`
                      : risk.classification === "Suspicious" || risk.classification === "High Risk"
                        ? `The analysis found ${positiveSignalCount} risk-contributing signal${positiveSignalCount === 1 ? "" : "s"}.${threat.status === "no_match" ? ` ${threat.source} returned no known match.` : threat.status === "unavailable" ? ` ${threat.source} was unavailable.` : ""}`
                        : risk.classification === "Low Risk"
                          ? "The checks found limited risk signals. A low score does not prove a website is safe."
                          : "The available checks did not provide enough evidence for a stronger conclusion."}
                </p>
                <div className="risk-meter-wrap">
                  <div className="risk-meter-label">
                    <span>Risk score</span>
                    <span>
                      {risk.score} <small>/ 100</small>
                    </span>
                  </div>
                  <progress
                    className={`risk-meter meter-${riskTone}`}
                    max="100"
                    value={risk.score}
                    aria-label={`Risk score ${risk.score} out of 100`}
                  />
                  <div className="risk-meter-scale">
                    <span>Lower signal</span>
                    <span>Higher signal</span>
                  </div>
                </div>
              </div>
              <div className="risk-side-metrics">
                <div className="risk-stat">
                  <span className="stat-label">Confidence</span>
                  <strong>
                    {Math.round(risk.confidence * 100)}
                    <small>%</small>
                  </strong>
                  <span className="stat-caption">Evidence coverage</span>
                </div>
                <div className="risk-stat">
                  <span className="stat-label">Signals recorded</span>
                  <strong>{risk.contributing_indicators.length}</strong>
                  <span className="stat-caption">Across analysis sources</span>
                </div>
              </div>
            </section>

            <section className="summary-findings" aria-labelledby="key-findings-title">
              <div className="summary-section-heading">
                <div>
                  <p className="eyebrow">CONCISE SUMMARY</p>
                  <h3 id="key-findings-title">Key findings</h3>
                </div>
                <span className="summary-quiet">Most relevant signals from this analysis</span>
              </div>
              {typo.detected && typo.submitted_domain && typo.possible_intended_site && (
                <section className="typo-callout" aria-label="Possible typosquatting correction">
                  <div className="typo-callout-icon" aria-hidden="true">
                    ↗
                  </div>
                  <div className="typo-copy">
                    <Pill tone="warning">Possible typo detected</Pill>
                    <p>
                      <strong className="typo-submitted is-mono">{typo.submitted_domain}</strong>{" "}
                      looks similar to{" "}
                      <strong className="typo-intended is-mono">
                        {typo.possible_intended_site}
                      </strong>
                      .
                    </p>
                    <p className="typo-suggestion">
                      Did you mean <strong>{typo.possible_intended_site}</strong>?
                    </p>
                  </div>
                </section>
              )}
              <ul className="key-findings-list">
                {findings
                  .filter((finding) => finding.title !== "Possible typosquatting")
                  .map((finding, index) => (
                    <li className="key-finding" key={`${finding.title}-${index}`}>
                      <span className={`key-finding-mark mark-${finding.tone}`} aria-hidden="true">
                        {finding.tone === "good" ? "✓" : finding.tone === "danger" ? "!" : "·"}
                      </span>
                      <span className="key-finding-copy">
                        <strong>{finding.title}</strong>
                        <span>{finding.detail}</span>
                      </span>
                    </li>
                  ))}
              </ul>
            </section>

            <section className="summary-overview" aria-labelledby="analysis-overview-title">
              <div className="summary-section-heading">
                <div>
                  <p className="eyebrow">AT A GLANCE</p>
                  <h3 id="analysis-overview-title">Analysis overview</h3>
                </div>
              </div>
              <div className="overview-grid" aria-label="Analysis source overview">
                <OverviewCard
                  title="URL analysis"
                  status={result.url_analysis.is_valid ? "ok" : "error"}
                  statusLabel={result.url_analysis.is_valid ? "VALID" : "INVALID"}
                  metric={`${result.url_analysis.scheme?.toUpperCase() ?? "URL"} · ${result.url_analysis.registered_domain ?? result.url_analysis.hostname ?? "No domain"}`}
                />
                <OverviewCard
                  title="DNS analysis"
                  status={result.dns_analysis.status}
                  statusLabel={
                    result.dns_analysis.resolution_succeeded ? "RESOLVED" : "UNAVAILABLE"
                  }
                  metric={`${result.dns_analysis.ipv4_addresses.length} IPv4 · ${result.dns_analysis.ipv6_addresses.length} IPv6`}
                />
                <OverviewCard
                  title="Phishing analysis"
                  status={result.phishing_analysis.is_suspicious ? "warning" : "ok"}
                  statusLabel={result.phishing_analysis.is_suspicious ? "WARNING" : "NO SIGNAL"}
                  metric={`${result.phishing_analysis.indicators.length} indicator${result.phishing_analysis.indicators.length === 1 ? "" : "s"}`}
                />
                <OverviewCard
                  title="Threat intelligence"
                  status={threat.status}
                  statusLabel={
                    threat.status === "matched"
                      ? "MATCH"
                      : threat.status === "no_match"
                        ? "NO MATCH"
                        : "UNAVAILABLE"
                  }
                  metric={threat.source}
                />
                <OverviewCard
                  title="TLS / Certificate"
                  status={
                    result.tls_analysis.status === "not_applicable"
                      ? "not_applicable"
                      : result.tls_analysis.connection_successful
                        ? result.tls_analysis.certificate_verified === true
                          ? "ok"
                          : "warning"
                        : "error"
                  }
                  statusLabel={
                    result.tls_analysis.status === "not_applicable"
                      ? "NOT APPLICABLE"
                      : result.tls_analysis.connection_successful
                        ? result.tls_analysis.certificate_verified === true
                          ? "SECURE"
                          : "CHECKED"
                        : "UNAVAILABLE"
                  }
                  metric={
                    result.tls_analysis.protocol_version ??
                    (result.tls_analysis.status === "not_applicable"
                      ? "TLS not used"
                      : "No protocol")
                  }
                />
                <OverviewCard
                  title="HTTP response"
                  status={
                    result.http_analysis.request_successful ? "ok" : result.http_analysis.status
                  }
                  statusLabel={result.http_analysis.request_successful ? "RECEIVED" : "UNAVAILABLE"}
                  metric={
                    result.http_analysis.status_code === null
                      ? "No status code"
                      : `HTTP ${result.http_analysis.status_code}${httpStatusText(result.http_analysis.status_code) ? ` ${httpStatusText(result.http_analysis.status_code)}` : ""}`
                  }
                />
                <OverviewCard
                  title="Typosquatting"
                  status={typo.detected ? "warning" : "ok"}
                  statusLabel={typo.detected ? "DETECTED" : "NO CLOSE MATCH"}
                  metric={
                    typo.detected
                      ? (typo.possible_intended_site ?? "Possible typo")
                      : "No close domain match"
                  }
                />
              </div>
            </section>

            <section className="risk-details-grid">
              <div className="panel evidence-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">TOP CONTRIBUTIONS</p>
                    <h3>
                      {risk.classification === "Suspicious" ||
                      risk.classification === "High Risk" ||
                      risk.classification === "Confirmed Malicious"
                        ? "Why is this suspicious?"
                        : "Why this result?"}
                    </h3>
                  </div>
                  <span className="panel-count">Top signals</span>
                </div>
                <p className="panel-hint">
                  The strongest available signals and their impact on the score.
                </p>
                {risk.contributing_indicators.filter((item) => item.weight !== 0).length === 0 ? (
                  <p className="empty-note">
                    No signal changed the score. This does not prove the URL is safe.
                  </p>
                ) : (
                  <ol className="evidence-timeline summary-evidence-list">
                    {[...risk.contributing_indicators]
                      .filter((item) => item.weight !== 0)
                      .sort((left, right) => Math.abs(right.weight) - Math.abs(left.weight))
                      .slice(0, 3)
                      .map((item, index) => (
                        <li
                          className="evidence-item"
                          key={`${item.source}-${item.indicator}-${index}`}
                        >
                          <span
                            className={`evidence-node ${item.weight > 0 ? "node-risk" : item.weight < 0 ? "node-counter" : "node-neutral"}`}
                            aria-hidden="true"
                          />
                          <div className="evidence-content">
                            <div className="evidence-topline">
                              <span className="evidence-source">
                                {item.source.replaceAll("_", " ")}
                              </span>
                              <span
                                className={`impact impact-${item.weight > 0 ? "risk" : item.weight < 0 ? "counter" : "neutral"}`}
                              >
                                {item.weight > 0 ? "+" : ""}
                                {item.weight} impact
                              </span>
                            </div>
                            <strong>{shortEvidenceTitle(item)}</strong>
                            <p>{shortEvidenceDescription(item)}</p>
                            <span className="evidence-meta">
                              {item.weight < 0 ? "Limited counterevidence" : "Risk contribution"}
                            </span>
                          </div>
                        </li>
                      ))}
                  </ol>
                )}
                <button
                  className="text-button"
                  type="button"
                  onClick={() => {
                    setDetailedOpen(true);
                    setRiskEvidenceOpen(true);
                    window.requestAnimationFrame(() => {
                      document
                        .getElementById("risk-evidence-detail")
                        ?.scrollIntoView({ behavior: "smooth", block: "center" });
                    });
                  }}
                >
                  View all evidence <span aria-hidden="true">→</span>
                </button>
              </div>
              <div className="notice-stack">
                <div className="notice-card notice-precautions">
                  <div className="notice-heading">
                    <span aria-hidden="true">✓</span>
                    <h3>Recommended action</h3>
                  </div>
                  <ul>
                    {risk.recommended_precautions.slice(0, 2).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>

            <details
              className="technical-details"
              open={detailedOpen}
              onToggle={(event) => {
                setDetailedOpen(event.currentTarget.open);
                if (!event.currentTarget.open) setRiskEvidenceOpen(false);
              }}
            >
              <summary className="technical-summary">
                <span className="technical-summary-icon" aria-hidden="true">
                  ⌄
                </span>
                <span className="technical-summary-copy">
                  <strong>Detailed analysis</strong>
                  <span>Technical evidence and diagnostics</span>
                </span>
                <span className="technical-summary-action">
                  {detailedOpen ? "Hide detailed analysis" : "Show detailed analysis"}
                </span>
              </summary>
              <section className="analysis-grid" aria-label="Detailed analysis results">
                <DetailPanel
                  title="URL analysis"
                  status={result.url_analysis.is_valid ? "ok" : "error"}
                  summary={
                    result.url_analysis.registered_domain ??
                    result.url_analysis.hostname ??
                    "URL structure"
                  }
                >
                  <KeyValueGrid
                    rows={[
                      {
                        label: "Original URL",
                        value: result.url_analysis.original_url,
                        mono: true,
                      },
                      {
                        label: "Normalized URL",
                        value: result.url_analysis.normalized_url,
                        mono: true,
                      },
                      { label: "Scheme", value: result.url_analysis.scheme },
                      { label: "Hostname", value: result.url_analysis.hostname, mono: true },
                      {
                        label: "Registered domain",
                        value: result.url_analysis.registered_domain,
                        mono: true,
                      },
                      { label: "Subdomain", value: result.url_analysis.subdomain, mono: true },
                      { label: "Public suffix", value: result.url_analysis.public_suffix },
                      { label: "Port", value: result.url_analysis.port },
                      { label: "Path", value: result.url_analysis.path, mono: true },
                      { label: "Query present", value: result.url_analysis.has_query },
                      { label: "Fragment present", value: result.url_analysis.has_fragment },
                      { label: "Username present", value: result.url_analysis.has_username },
                      { label: "Password present", value: result.url_analysis.has_password },
                      { label: "IP address hostname", value: result.url_analysis.is_ip_address },
                      { label: "Syntactically valid", value: result.url_analysis.is_valid },
                      { label: "Validation error", value: result.url_analysis.validation_error },
                    ]}
                  />
                </DetailPanel>

                <DetailPanel
                  title="DNS analysis"
                  status={result.dns_analysis.status}
                  summary={`${result.dns_analysis.ipv4_addresses.length} A · ${result.dns_analysis.ipv6_addresses.length} AAAA records`}
                >
                  <KeyValueGrid
                    rows={[
                      { label: "Hostname", value: result.dns_analysis.hostname, mono: true },
                      { label: "Status", value: result.dns_analysis.status },
                      {
                        label: "Resolution succeeded",
                        value: result.dns_analysis.resolution_succeeded,
                      },
                      { label: "CNAME", value: result.dns_analysis.cname_target, mono: true },
                      { label: "Reason", value: result.dns_analysis.reason },
                    ]}
                  />
                  <h4>A records</h4>
                  <ValueList items={result.dns_analysis.ipv4_addresses} />
                  <h4>AAAA records</h4>
                  <ValueList items={result.dns_analysis.ipv6_addresses} />
                  <h4>MX records</h4>
                  {result.dns_analysis.mail_servers.length === 0 ? (
                    <p className="empty-note">None reported</p>
                  ) : (
                    <ValueList
                      items={result.dns_analysis.mail_servers.map(
                        (record) => `${record.preference} ${record.exchange}`,
                      )}
                    />
                  )}
                  <h4>Nameservers</h4>
                  <ValueList items={result.dns_analysis.nameservers} />
                  <h4>TXT records</h4>
                  <ValueList items={result.dns_analysis.txt_records} />
                  <h4>DNS errors</h4>
                  {result.dns_analysis.errors.length === 0 ? (
                    <p className="empty-note">None reported</p>
                  ) : (
                    <ul className="record-list">
                      {result.dns_analysis.errors.map((item, index) => (
                        <li key={`${item.record_type}-${index}`}>
                          <strong>
                            {item.record_type} · {item.error_type}
                          </strong>
                          <span>{item.message}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </DetailPanel>

                <DetailPanel
                  title="Phishing analysis"
                  status={result.phishing_analysis.is_suspicious ? "warning" : "ok"}
                  summary={`Score ${result.phishing_analysis.score} · ${result.phishing_analysis.indicators.length} indicators`}
                >
                  <KeyValueGrid
                    rows={[
                      { label: "Suspicious", value: result.phishing_analysis.is_suspicious },
                      { label: "Phishing score", value: result.phishing_analysis.score },
                      { label: "fraudurl status", value: result.phishing_analysis.fraudurl.status },
                      {
                        label: "fraudurl score contribution",
                        value: result.phishing_analysis.fraudurl.score_contribution,
                      },
                      { label: "fraudurl error", value: result.phishing_analysis.fraudurl.error },
                    ]}
                  />
                  <h4>Indicators</h4>
                  {result.phishing_analysis.indicators.length === 0 ? (
                    <p className="empty-note">No indicators reported</p>
                  ) : (
                    <div className="indicator-list">
                      {result.phishing_analysis.indicators.map((indicator, index) => (
                        <article className="indicator-card" key={`${indicator.type}-${index}`}>
                          <div className="indicator-heading">
                            <strong>{indicator.type.replaceAll("_", " ")}</strong>
                            <Pill
                              tone={
                                indicator.severity === "high"
                                  ? "danger"
                                  : indicator.severity === "medium"
                                    ? "warning"
                                    : "neutral"
                              }
                            >
                              {indicator.severity}
                            </Pill>
                          </div>
                          <p>{indicator.description}</p>
                          <div className="evidence-box">
                            <span>Evidence</span>
                            {indicator.evidence}
                          </div>
                          <span className="indicator-impact">
                            Analyzer contribution: {indicator.score_contribution}
                          </span>
                        </article>
                      ))}
                    </div>
                  )}
                  <h4>fraudurl result</h4>
                  {fraudResult === null ? (
                    <p className="empty-note">No result returned</p>
                  ) : (
                    <KeyValueGrid
                      rows={Object.entries(fraudResult).map(([label, value]) => ({
                        label: label.replaceAll("_", " "),
                        value,
                      }))}
                    />
                  )}
                </DetailPanel>

                <DetailPanel
                  title="Threat intelligence"
                  status={threat.status}
                  summary={`${threat.source} · ${threat.status === "matched" ? "Match found" : threat.status === "no_match" ? "No match" : "Unavailable"}`}
                  className={threat.status === "matched" ? "detail-threat-match" : ""}
                >
                  <KeyValueGrid
                    rows={[
                      { label: "Provider", value: threat.source },
                      { label: "Match status", value: threat.status },
                      { label: "Matched", value: threat.matched },
                      { label: "Match scope", value: threat.match_scope },
                      { label: "Threat type", value: threat.threat_type },
                      { label: "Confidence", value: threat.confidence },
                      { label: "Indicator", value: threat.indicator, mono: true },
                      { label: "Reference", value: threat.reference, mono: true },
                      { label: "Checked at", value: threat.checked_at },
                      { label: "Provider error", value: threat.error },
                    ]}
                  />
                  <h4>Provider evidence</h4>
                  <KeyValueGrid
                    rows={Object.entries(threat.evidence).map(([label, value]) => ({
                      label,
                      value,
                    }))}
                  />
                </DetailPanel>

                <DetailPanel
                  title="TLS / Certificate"
                  status={result.tls_analysis.status}
                  summary={`${result.tls_analysis.protocol_version ?? "Protocol unavailable"} · ${result.tls_analysis.hostname ?? "No hostname"}`}
                >
                  <KeyValueGrid
                    rows={[
                      { label: "Supported", value: result.tls_analysis.supported },
                      {
                        label: "Connection successful",
                        value: result.tls_analysis.connection_successful,
                      },
                      { label: "Hostname", value: result.tls_analysis.hostname, mono: true },
                      { label: "Port", value: result.tls_analysis.port },
                      { label: "Protocol version", value: result.tls_analysis.protocol_version },
                      {
                        label: "Certificate verified",
                        value: result.tls_analysis.certificate_verified,
                      },
                    ]}
                  />
                  {result.tls_analysis.certificate && (
                    <>
                      <h4>Peer certificate</h4>
                      <KeyValueGrid
                        rows={[
                          { label: "Subject", value: result.tls_analysis.certificate.subject },
                          { label: "Issuer", value: result.tls_analysis.certificate.issuer },
                          {
                            label: "Serial number",
                            value: result.tls_analysis.certificate.serial_number,
                            mono: true,
                          },
                          {
                            label: "Valid from",
                            value: result.tls_analysis.certificate.not_before,
                          },
                          {
                            label: "Valid until",
                            value: result.tls_analysis.certificate.not_after,
                          },
                          { label: "Expired", value: result.tls_analysis.certificate.is_expired },
                          {
                            label: "Hostname matches",
                            value: result.tls_analysis.certificate.hostname_matches,
                          },
                          {
                            label: "Public key algorithm",
                            value: result.tls_analysis.certificate.public_key_algorithm,
                          },
                          {
                            label: "Public key size",
                            value: result.tls_analysis.certificate.public_key_size
                              ? `${result.tls_analysis.certificate.public_key_size} bits`
                              : null,
                          },
                          {
                            label: "Signature algorithm",
                            value: result.tls_analysis.certificate.signature_algorithm,
                          },
                        ]}
                      />
                      <h4>Subject alternative names</h4>
                      <ValueList items={result.tls_analysis.certificate.san_names} />
                    </>
                  )}
                  <h4>Certificate chain</h4>
                  {result.tls_analysis.certificate_chain.length === 0 ? (
                    <p className="empty-note">No chain entries available</p>
                  ) : (
                    <ul className="record-list">
                      {result.tls_analysis.certificate_chain.map((cert, index) => (
                        <li key={`${cert.serial_number}-${index}`}>
                          <strong>{cert.subject}</strong>
                          <span>
                            Issuer: {cert.issuer} · Serial: {cert.serial_number}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <h4>Transparency and revocation</h4>
                  <KeyValueGrid
                    rows={[
                      {
                        label: "Certificate Transparency",
                        value: `${result.tls_analysis.certificate_transparency.status}: ${result.tls_analysis.certificate_transparency.reason}`,
                      },
                      {
                        label: "Certificate revocation",
                        value: `${result.tls_analysis.certificate_revocation.status}: ${result.tls_analysis.certificate_revocation.reason}`,
                      },
                    ]}
                  />
                  <h4>TLS findings</h4>
                  {result.tls_analysis.findings.length === 0 ? (
                    <p className="empty-note">None reported</p>
                  ) : (
                    <div className="indicator-list">
                      {result.tls_analysis.findings.map((finding, index) => (
                        <article className="indicator-card" key={`${finding.type}-${index}`}>
                          <div className="indicator-heading">
                            <strong>{finding.description}</strong>
                            <Pill tone={finding.severity === "high" ? "danger" : "warning"}>
                              {finding.severity}
                            </Pill>
                          </div>
                          <span className="indicator-impact">
                            Finding type: {finding.type.replaceAll("_", " ")}
                          </span>
                          <p>{finding.evidence}</p>
                        </article>
                      ))}
                    </div>
                  )}
                  <p className="trust-note">{result.tls_analysis.trust_note}</p>
                </DetailPanel>

                <DetailPanel
                  title="HTTP response"
                  status={result.http_analysis.status}
                  summary={`${result.http_analysis.request_method} · ${result.http_analysis.status_code === null ? "No status" : `HTTP ${result.http_analysis.status_code}`}`}
                >
                  <KeyValueGrid
                    rows={[
                      { label: "Status", value: result.http_analysis.status },
                      { label: "Supported", value: result.http_analysis.supported },
                      {
                        label: "Request successful",
                        value: result.http_analysis.request_successful,
                      },
                      { label: "Request method", value: result.http_analysis.request_method },
                      {
                        label: "Requested URL",
                        value: result.url_analysis.normalized_url,
                        mono: true,
                      },
                      { label: "Scheme", value: result.http_analysis.scheme },
                      { label: "Hostname", value: result.http_analysis.hostname, mono: true },
                      { label: "Port", value: result.http_analysis.port },
                      { label: "HTTP status code", value: result.http_analysis.status_code },
                      { label: "Final behavior", value: result.http_analysis.final_behavior },
                      {
                        label: "Headers size",
                        value:
                          result.http_analysis.headers_size_bytes === null
                            ? null
                            : `${result.http_analysis.headers_size_bytes} bytes`,
                      },
                      { label: "Redirect detected", value: result.http_analysis.redirect_detected },
                      {
                        label: "Redirect status",
                        value: result.http_analysis.redirect_status_code,
                      },
                      {
                        label: "Redirect location (not followed)",
                        value: result.http_analysis.redirect_location,
                        mono: true,
                      },
                      { label: "Error", value: result.http_analysis.error },
                    ]}
                  />
                  <h4>Security headers</h4>
                  <ul className="header-list">
                    {Object.entries(result.http_analysis.security_headers).map(([name, value]) => (
                      <li key={name}>
                        <span className="header-name is-mono">{name}</span>
                        <span
                          className={`header-value ${value ? "header-present" : "header-missing"}`}
                        >
                          <i />
                          {value ? "Present" : "Missing"}
                        </span>
                        {value && <code>{value}</code>}
                      </li>
                    ))}
                  </ul>
                  <h4>HTTP findings</h4>
                  {result.http_analysis.findings.length === 0 ? (
                    <p className="empty-note">None reported</p>
                  ) : (
                    <div className="indicator-list">
                      {result.http_analysis.findings.map((finding, index) => (
                        <article className="indicator-card" key={`${finding.type}-${index}`}>
                          <div className="indicator-heading">
                            <strong>{finding.description}</strong>
                            <Pill
                              tone={
                                finding.severity === "high"
                                  ? "danger"
                                  : finding.severity === "medium"
                                    ? "warning"
                                    : "neutral"
                              }
                            >
                              {finding.severity}
                            </Pill>
                          </div>
                          <span className="indicator-impact">
                            Finding type: {finding.type.replaceAll("_", " ")}
                          </span>
                          <p>{finding.evidence}</p>
                          <span className="indicator-impact">
                            Analyzer contribution: {finding.score_contribution}
                          </span>
                        </article>
                      ))}
                    </div>
                  )}
                  <p className="trust-note">{result.http_analysis.trust_note}</p>
                </DetailPanel>
                <DetailPanel
                  id="risk-evidence-detail"
                  title="Risk evidence"
                  status={`${risk.contributing_indicators.length} items`}
                  summary="Sources, evidence, and score impact"
                  open={riskEvidenceOpen}
                  onToggle={setRiskEvidenceOpen}
                >
                  <p className="panel-hint">
                    Complete explanation of the evidence considered by the risk assessment.
                  </p>
                  <EvidenceList items={risk.contributing_indicators} />
                </DetailPanel>
                <DetailPanel
                  title="Limitations and precautions"
                  status="review"
                  summary={`${risk.recommended_precautions.length} precautions · ${risk.limitations.length} limitations`}
                >
                  <h4>Recommended precautions</h4>
                  {risk.recommended_precautions.length === 0 ? (
                    <p className="empty-note">None provided</p>
                  ) : (
                    <ul className="technical-list">
                      {risk.recommended_precautions.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  )}
                  <h4>Analysis limitations</h4>
                  {risk.limitations.length === 0 ? (
                    <p className="empty-note">None reported</p>
                  ) : (
                    <ul className="technical-list">
                      {risk.limitations.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  )}
                </DetailPanel>
              </section>
            </details>
            <footer className="report-footer">
              Automated checks provide evidence for review; they do not prove a website is safe or
              legitimate.
            </footer>
          </section>
        )}
      </main>
      <footer className="site-footer">
        <span>Web Threat Intelligence</span>
        <span>Evidence-led analysis · No automated browsing</span>
      </footer>
    </div>
  );
}

export default App;
