export function AnalyzeButton({ loading }: { loading: boolean }) {
  return <button className="analyze-button" type="submit" disabled={loading}>{loading ? <span className="spinner" /> : null}{loading ? "Analyzing content" : "Analyze content"}{!loading ? <span aria-hidden="true">→</span> : null}</button>;
}
