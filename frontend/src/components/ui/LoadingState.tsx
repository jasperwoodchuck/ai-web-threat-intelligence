export function LoadingState() {
  return <div className="loading-card" role="status"><span className="spinner spinner-dark" /><span><strong>Analyzing content</strong><small>Checking structure · evaluating security signals · preparing report</small></span><span className="loading-progress" aria-hidden="true"><i /></span></div>;
}
