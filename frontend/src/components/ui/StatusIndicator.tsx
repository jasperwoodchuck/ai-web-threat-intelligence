export function StatusIndicator({ label, detail }: { label: string; detail?: string }) {
  return <div className="system-status"><span className="live-indicator" /><span><strong>{label}</strong>{detail && <small>{detail}</small>}</span></div>;
}
