import { INVESTIGATION_MODE_ORDER, INVESTIGATION_MODES } from "../../constants/investigation";
import type { AnalysisMode } from "../../types/investigation";

export function InvestigationModeSelector({ mode, onChange, disabled }: { mode: AnalysisMode; onChange: (mode: AnalysisMode) => void; disabled: boolean }) {
  return <div className="mode-switch" role="tablist" aria-label="Investigation type">
    {INVESTIGATION_MODE_ORDER.map((id) => {
      const config = INVESTIGATION_MODES[id];
      return <button key={id} type="button" role="tab" aria-selected={mode === id} disabled={disabled} className={mode === id ? "is-active" : ""} onClick={() => onChange(id)}>
        {config.icon === "url" ? <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.2 2.3 3.3 5.1 3.3 8.5s-1.1 6.2-3.3 8.5c-2.2-2.3-3.3-5.1-3.3-8.5S9.8 5.8 12 3.5Z" /></svg> : <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3" /><path d="m4 7 8 6 8-6" /></svg>}
        <span>{config.label}</span><small>{config.description}</small>
      </button>;
    })}
  </div>;
}
