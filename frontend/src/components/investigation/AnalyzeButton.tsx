export function AnalyzeButton({ loading, mode }: { loading: boolean; mode: "url" | "message" | "file" }) {
  const labels = { url: "Analyze website", message: "Analyze message", file: "Analyze file" };
  return <button className="analyze-button" type="submit" disabled={loading}>{loading ? <span className="spinner" /> : null}{loading ? "Analyzing content" : labels[mode]}{!loading ? <span aria-hidden="true">→</span> : null}</button>;
}
