import type { ReactNode } from "react";
import { useState } from "react";
import { Badge as Pill } from "../ui/Badge";
import type { KeyValue, RiskEvidence } from "../../types/investigation";
import { displayValue } from "../../lib/formatters";
import { statusTone } from "../../lib/analysis";
import { AnalysisDetailModal, type AnalysisCardDetail } from "./AnalysisDetailModal";

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
  detailsAvailable = true,
}: {
  title: string;
  status: string;
  summary: string;
  children: ReactNode;
  className?: string;
  detailsAvailable?: boolean;
}) {
  const [detail, setDetail] = useState<AnalysisCardDetail | null>(null);

  return (
    <>
      {detailsAvailable ? (
        <button
          type="button"
          className={`detail-panel detail-panel-trigger ${className}`}
          aria-haspopup="dialog"
          aria-label={`${title}: ${status}. Open details.`}
          onClick={() =>
            setDetail({ title, status, data: null, content: <div className="detail-content">{children}</div> })
          }
        >
          <span className="detail-title-block">
            <span className="detail-title">{title}</span>
            <span className="detail-summary">{summary}</span>
          </span>
          <Pill tone={statusTone(status)}>{status.replaceAll("_", " ")}</Pill>
          <span className="detail-panel-open" aria-hidden="true" title="Open details">
            ↗
          </span>
        </button>
      ) : (
        <div className={`detail-panel detail-panel-static ${className}`}>
          <span className="detail-title-block">
            <span className="detail-title">{title}</span>
            <span className="detail-summary">{summary}</span>
          </span>
          <Pill tone={statusTone(status)}>{status.replaceAll("_", " ")}</Pill>
        </div>
      )}
      {detail && <AnalysisDetailModal detail={detail} onClose={() => setDetail(null)} />}
    </>
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



