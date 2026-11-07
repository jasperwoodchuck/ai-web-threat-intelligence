import { useState, type FormEvent } from "react";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<unknown>(null);
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

      setResult(payload);
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
        {result !== null && <pre>{JSON.stringify(result, null, 2)}</pre>}
      </section>
    </main>
  );
}
