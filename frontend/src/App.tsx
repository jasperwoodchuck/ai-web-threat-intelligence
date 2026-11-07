import { useState, type FormEvent } from "react";

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
  errors: { record_type: string; error_type: string; message: string }[];
  reason: string | null;
}

interface PhishingIndicator {
  type: string;
  severity: string;
  description: string;
  evidence: string;
  score_contribution: number;
}

interface PhishingAnalysis {
  is_suspicious: boolean;
  score: number;
  indicators: PhishingIndicator[];
  fraudurl: {
    status: string;
    result: Record<string, unknown> | null;
    score_contribution: number;
    error: string | null;
  };
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

interface TlsAnalysis {
  status: string;
  supported: boolean;
  connection_successful: boolean;
  hostname: string | null;
  port: number | null;
  protocol_version: string | null;
  certificate_verified: boolean | null;
  certificate: {
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
  } | null;
  certificate_chain: { subject: string; issuer: string; serial_number: string }[];
  certificate_transparency: { status: string; reason: string };
  certificate_revocation: { status: string; reason: string };
  findings: { type: string; severity: string; description: string; evidence: string }[];
  trust_note: string;
}

interface UrlAnalysisResponse {
  url_analysis: Record<string, unknown>;
  dns_analysis: DnsAnalysis;
  phishing_analysis: PhishingAnalysis;
  risk_assessment: RiskAssessment;
  tls_analysis: TlsAnalysis;
}

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleAnalyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedUrl = url.trim();
    setError("");
    setResult(null);

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

  return (
    <main>
      <h1>Web Threat Intelligence</h1>
      <p>Analyze a URL to inspect its structure and domain information.</p>

      <form onSubmit={handleAnalyze}>
        <label htmlFor="url">URL</label>
        <input
          id="url"
          type="url"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com"
        />
        <button type="submit" disabled={loading}>
          {loading ? "Analyzing…" : "Analyze URL"}
        </button>
      </form>

      <section aria-live="polite">
        <h2>Results</h2>
        {loading && <p>Analyzing URL…</p>}
        {error && <p role="alert">{error}</p>}
        {result !== null && (
          <>
            <h3>URL Analysis</h3>
            <pre>{JSON.stringify(result.url_analysis, null, 2)}</pre>
            <h3>DNS Analysis</h3>
            <p>Status: {result.dns_analysis.status}</p>
            <p>A Records: {result.dns_analysis.ipv4_addresses.join(", ") || "None"}</p>
            <p>AAAA Records: {result.dns_analysis.ipv6_addresses.join(", ") || "None"}</p>
            <p>CNAME: {result.dns_analysis.cname_target ?? "None"}</p>
            <p>
              MX Records:{" "}
              {result.dns_analysis.mail_servers
                .map((server) => `${server.preference} ${server.exchange}`)
                .join(", ") || "None"}
            </p>
            <p>NS Records: {result.dns_analysis.nameservers.join(", ") || "None"}</p>
            <p>TXT Records: {result.dns_analysis.txt_records.join("; ") || "None"}</p>
            {result.dns_analysis.reason && <p>{result.dns_analysis.reason}</p>}
            {result.dns_analysis.errors.length > 0 && (
              <ul>
                {result.dns_analysis.errors.map((item, index) => (
                  <li key={`${item.record_type}-${index}`}>
                    {item.record_type}: {item.error_type} — {item.message}
                  </li>
                ))}
              </ul>
            )}
            <h3>Phishing Analysis</h3>
            <p>Suspicious: {result.phishing_analysis.is_suspicious ? "Yes" : "No"}</p>
            <p>Score: {result.phishing_analysis.score}</p>
            <h4>Indicators:</h4>
            {result.phishing_analysis.indicators.length === 0 ? (
              <p>None</p>
            ) : (
              <ul>
                {result.phishing_analysis.indicators.map((indicator, index) => (
                  <li key={`${indicator.type}-${index}`}>
                    {indicator.description} Evidence: {indicator.evidence} (severity:{" "}
                    {indicator.severity}; score contribution: {indicator.score_contribution})
                  </li>
                ))}
              </ul>
            )}
            <p>fraudurl signal: {result.phishing_analysis.fraudurl.status}</p>
            {result.phishing_analysis.fraudurl.result !== null && (
              <pre>{JSON.stringify(result.phishing_analysis.fraudurl.result, null, 2)}</pre>
            )}
            {result.phishing_analysis.fraudurl.error && (
              <p>fraudurl unavailable: {result.phishing_analysis.fraudurl.error}</p>
            )}
            <h3>Risk Assessment</h3>
            <p>Classification: {result.risk_assessment.classification}</p>
            <p>Score: {result.risk_assessment.score}</p>
            <p>Confidence: {result.risk_assessment.confidence.toFixed(2)}</p>
            <h4>Why:</h4>
            {result.risk_assessment.contributing_indicators.length === 0 ? (
              <p>No contributing indicators. The result is inconclusive.</p>
            ) : (
              <ul>
                {result.risk_assessment.contributing_indicators.map((item, index) => (
                  <li key={`${item.source}-${item.indicator}-${index}`}>
                    {item.description} Evidence: {item.evidence} (source: {item.source}; weight:{" "}
                    {item.weight})
                  </li>
                ))}
              </ul>
            )}
            <h4>Precautions:</h4>
            <ul>
              {result.risk_assessment.recommended_precautions.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <h4>Limitations:</h4>
            <ul>
              {result.risk_assessment.limitations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <h3>TLS / Certificate Analysis</h3>
            {result.tls_analysis.status === "not_applicable" ? (
              <p>TLS analysis not applicable — URL uses HTTP.</p>
            ) : (
              <>
                <p>TLS supported: {result.tls_analysis.supported ? "Yes" : "No"}</p>
                <p>
                  Connection: {result.tls_analysis.connection_successful ? "Successful" : "Failed"}
                </p>
                <p>Protocol: {result.tls_analysis.protocol_version ?? "Unavailable"}</p>
                <p>
                  Certificate chain verified:{" "}
                  {result.tls_analysis.certificate_verified === null
                    ? "Unknown"
                    : result.tls_analysis.certificate_verified
                      ? "Yes"
                      : "No"}
                </p>
                <p>
                  Certificate subject: {result.tls_analysis.certificate?.subject ?? "Unavailable"}
                </p>
                <p>
                  Certificate issuer: {result.tls_analysis.certificate?.issuer ?? "Unavailable"}
                </p>
                <p>Valid from: {result.tls_analysis.certificate?.not_before ?? "Unavailable"}</p>
                <p>Valid until: {result.tls_analysis.certificate?.not_after ?? "Unavailable"}</p>
                <p>
                  Expired:{" "}
                  {result.tls_analysis.certificate?.is_expired === null ||
                  result.tls_analysis.certificate === null
                    ? "Unknown"
                    : result.tls_analysis.certificate.is_expired
                      ? "Yes"
                      : "No"}
                </p>
                <p>
                  SAN names:{" "}
                  {result.tls_analysis.certificate?.san_names.join(", ") ?? "Unavailable"}
                </p>
                <p>
                  Hostname matches:{" "}
                  {result.tls_analysis.certificate?.hostname_matches === null ||
                  result.tls_analysis.certificate === null
                    ? "Unknown"
                    : result.tls_analysis.certificate.hostname_matches
                      ? "Yes"
                      : "No"}
                </p>
                <p>
                  Public key:{" "}
                  {result.tls_analysis.certificate?.public_key_algorithm ?? "Unavailable"}
                  {result.tls_analysis.certificate?.public_key_size
                    ? ` (${result.tls_analysis.certificate.public_key_size} bits)`
                    : ""}
                </p>
                <p>
                  Signature algorithm:{" "}
                  {result.tls_analysis.certificate?.signature_algorithm ?? "Unavailable"}
                </p>
                <p>
                  Certificate Transparency: {result.tls_analysis.certificate_transparency.status}
                </p>
                <p>Certificate revocation: {result.tls_analysis.certificate_revocation.status}</p>
                <p>{result.tls_analysis.trust_note}</p>
                <h4>Findings:</h4>
                {result.tls_analysis.findings.length === 0 ? (
                  <p>None</p>
                ) : (
                  <ul>
                    {result.tls_analysis.findings.map((finding, index) => (
                      <li key={`${finding.type}-${index}`}>
                        {finding.description} Evidence: {finding.evidence}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </>
        )}
      </section>
    </main>
  );
}
