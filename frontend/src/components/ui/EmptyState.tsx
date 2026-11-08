export function EmptyState() {
  return <section className="empty-state"><div className="empty-visual" aria-hidden="true">
    <svg className="empty-network-graphic" viewBox="0 0 164 88" fill="none">
      <path className="network-edge" d="M42 24 72 38M122 19 94 38M128 65 94 50M42 24 18 31" />
      <path className="network-edge network-edge-muted" d="M42 24 42 63M122 19 122 44" />
      <rect className="network-node network-node-cyan" x="34" y="16" width="11" height="11" />
      <rect className="network-node network-node-blue" x="117" y="14" width="11" height="11" />
      <rect className="network-node network-node-violet" x="123" y="59" width="11" height="11" />
      <rect className="network-core" x="70" y="35" width="25" height="25" />
      <path className="network-core-mark" d="m78 45 4 4 6-8" />
    </svg>
  </div><div className="empty-copy"><p className="eyebrow">INVESTIGATION RESULTS</p><h2>Ready to investigate</h2><p>Select URL or Text Message, provide the content, and start an analysis.</p></div></section>;
}
