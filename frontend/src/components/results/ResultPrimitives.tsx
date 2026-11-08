import type { ReactNode } from "react";
import { Badge as Pill } from "../ui/Badge";
import type { KeyValue, RiskEvidence } from "../../types/investigation";
import { displayValue } from "../../lib/formatters";
import { statusTone } from "../../lib/analysis";

export function KeyValueGrid({ rows }: { rows: KeyValue[] }) {
  return (
    <dl className="key-value-grid">
      {rows.map((row) => (
        <div className="key-value" key={row.label}>
          <dt>{row.label}</dt>
          <dd className={row.mono ? "is-mono" : undefined}>{displayValue(row.value)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ValueList({ items, empty = "None reported" }: { items: string[]; empty?: string }) {
  if (items.length === 0) return <p className="empty-note">{empty}</p>;
  return (
    <ul className="compact-list">
      {items.map((item, index) => (
        <li className="value-chip is-mono" key={`${item}-${index}`}>
          {item}
        </li>
      ))}
    </ul>
  );
}

export function DetailPanel({
  title,
  status,
  summary,
  children,
  className = "",
  id,
  open,
  onToggle,
}: {
  title: string;
  status: string;
  summary: string;
  children: ReactNode;
  className?: string;
  id?: string;
  open?: boolean;
  onToggle?: (open: boolean) => void;
}) {
  return (
    <details
      id={id}
      className={`detail-panel ${className}`}
      open={open}
      onToggle={onToggle ? (event) => onToggle(event.currentTarget.open) : undefined}
    >
      <summary>
        <span className="detail-title-block">
          <span className="detail-title">{title}</span>
          <span className="detail-summary">{summary}</span>
        </span>
        <Pill tone={statusTone(status)}>{status.replaceAll("_", " ")}</Pill>
      </summary>
      <div className="detail-content">{children}</div>
    </details>
  );
}

export function OverviewCard({
  title,
  status,
  statusLabel,
  metric,
}: {
  title: string;
  status: string;
  statusLabel: string;
  metric: string;
}) {
  return (
    <div className="overview-card">
      <div className="overview-card-top">
        <span className="overview-title">{title}</span>
      </div>
      <Pill tone={statusTone(status)}>{statusLabel}</Pill>
      <strong className="overview-metric">{metric}</strong>
    </div>
  );
}

export function EvidenceList({ items }: { items: RiskEvidence[] }) {
  if (items.length === 0) return <p className="empty-note">No evidence items were returned.</p>;
  return (
    <ol className="evidence-timeline">
      {items.map((item, index) => (
        <li className="evidence-item" key={`${item.source}-${item.indicator}-${index}`}>
          <span
            className={`evidence-node ${item.weight > 0 ? "node-risk" : item.weight < 0 ? "node-counter" : "node-neutral"}`}
            aria-hidden="true"
          />
          <div className="evidence-content">
            <div className="evidence-topline">
              <span className="evidence-source">{item.source.replaceAll("_", " ")}</span>
              <span
                className={`impact impact-${item.weight > 0 ? "risk" : item.weight < 0 ? "counter" : "neutral"}`}
              >
                {item.weight > 0 ? "+" : ""}
                {item.weight} impact
              </span>
            </div>
            <strong>{item.description}</strong>
            <p>{item.evidence}</p>
            <span className="evidence-meta">
              {item.indicator.replaceAll("_", " ")} · {item.severity} severity
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}



