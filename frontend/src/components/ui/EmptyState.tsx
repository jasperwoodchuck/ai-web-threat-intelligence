export function EmptyState() {
  return <section className="empty-state"><div className="empty-visual" aria-hidden="true">
    <span className="empty-pulse empty-pulse-outer" /><span className="empty-pulse empty-pulse-inner" />
    <svg className="empty-shield-mark" viewBox="0 0 48 48" fill="none">
      <path className="empty-shield-fill" d="M24 4 40 10v12c0 10-6.5 17.5-16 22C14.5 39.5 8 32 8 22V10l16-6Z" />
      <path className="empty-shield-check" d="m16.5 23.5 5 5 10-11" />
    </svg>
  </div><div className="empty-copy"><p className="eyebrow">INVESTIGATION RESULTS</p><h2>Ready to investigate</h2><p>Select URL or Text Message, provide the content, and start an analysis.</p></div></section>;
}
