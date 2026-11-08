import { useEffect, useState } from "react";

const STATUS_INTERVAL_MS = 3_000;
const MAX_PENDING_PROGRESS = 92;
const MIN_PROGRESS_STEP_PERCENT = 1;
const MAX_PROGRESS_STEP_PERCENT = 9;

const ANALYSIS_STATUSES = [
  "Initializing security analysis...",
  "Preparing submitted content...",
  "Reading available analysis data...",
  "Inspecting content metadata...",
  "Reviewing the available response...",
  "Following relevant analysis steps...",
  "Analyzing submitted content...",
  "Extracting security indicators...",
  "Reviewing available analysis signals...",
  "Comparing detected indicators...",
  "Correlating available evidence...",
  "Preparing analysis results...",
];

export function LoadingState() {
  const [elapsedSteps, setElapsedSteps] = useState(0);
  const [progress, setProgress] = useState(5);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      setElapsedSteps((steps) => steps + 1);
      const step =
        MIN_PROGRESS_STEP_PERCENT +
        Math.random() * (MAX_PROGRESS_STEP_PERCENT - MIN_PROGRESS_STEP_PERCENT);
      setProgress((current) => Math.min(MAX_PENDING_PROGRESS, current + step));
    }, STATUS_INTERVAL_MS);

    return () => window.clearInterval(intervalId);
  }, []);

  const status = ANALYSIS_STATUSES[elapsedSteps] ?? "Finalizing analysis...";

  return (
    <div className="loading-card" role="status" aria-live="polite">
      <span className="spinner spinner-dark" aria-hidden="true" />
      <span className="loading-copy">
        <strong key={status} className="loading-status">
          {status}
        </strong>
        <small>Analysis is in progress. The service is processing your request.</small>
      </span>
      <span
        className="loading-progress"
        role="progressbar"
        aria-label="Simulated analysis progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(progress)}
      >
        <i style={{ width: `${progress}%` }} />
      </span>
    </div>
  );
}
