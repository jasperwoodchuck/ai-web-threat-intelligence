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

interface UrlAnalysisResponse {
  url_analysis: Record<string, unknown>;
  dns_analysis: DnsAnalysis;
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
          </>
        )}
      </section>
    </main>
  );
}
