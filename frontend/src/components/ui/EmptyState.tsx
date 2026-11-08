export function EmptyState() {
  return <section className="empty-state"><div className="empty-visual" aria-hidden="true"><span className="empty-network-line" /><span className="empty-network-node node-a" /><span className="empty-network-node node-b" /><span className="empty-network-node node-c" /><span className="empty-state-icon">⌁</span></div><div className="empty-copy"><p className="eyebrow">INVESTIGATION RESULTS</p><h2>Ready to investigate</h2><p>Select URL or Text Message, provide the content, and start an analysis.</p></div></section>;
}
