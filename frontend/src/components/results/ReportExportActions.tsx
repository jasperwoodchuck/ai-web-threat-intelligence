import { useEffect, useRef, useState } from "react";
import type { AnalysisApiResult } from "../../lib/reportExport";
import { createSanitizedReport, formatSanitizedSummary } from "../../lib/reportExport";

export function ReportExportActions({ result }: { result: AnalysisApiResult }) {
  const [feedback, setFeedback] = useState("");
  const [copied, setCopied] = useState(false);
  const copyResetTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(copyResetTimer.current), []);

  function downloadReport() {
    const report = createSanitizedReport(result);
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], {
      type: "application/json;charset=utf-8",
    });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `web-threat-analysis-${report.exported_at.slice(0, 10)}.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
    setFeedback("Sanitized report downloaded.");
  }

  async function copySummary() {
    try {
      const summary = formatSanitizedSummary(createSanitizedReport(result));
      await navigator.clipboard.writeText(summary);
      window.clearTimeout(copyResetTimer.current);
      setCopied(true);
      setFeedback("Sanitized summary copied.");
      copyResetTimer.current = window.setTimeout(() => setCopied(false), 2000);
    } catch {
      window.clearTimeout(copyResetTimer.current);
      setCopied(false);
      setFeedback("Could not copy the summary. Try downloading the JSON report instead.");
    }
  }

  return (
    <div className="report-export-wrap">
      <div className="report-export-actions" aria-label="Export analysis">
        <button
          type="button"
          className={`report-export-button${copied ? " is-copied" : ""}`}
          onClick={copySummary}
        >
          {copied ? <><span aria-hidden="true">✓</span> Copied</> : "Copy summary"}
        </button>
        <button type="button" className="report-export-button" onClick={downloadReport}>
          Download JSON
        </button>
      </div>
      <span className="report-export-feedback" role="status" aria-live="polite">
        {feedback}
      </span>
    </div>
  );
}
