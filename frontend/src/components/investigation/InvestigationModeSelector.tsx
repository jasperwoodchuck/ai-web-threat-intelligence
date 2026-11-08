import { INVESTIGATION_MODE_ORDER, INVESTIGATION_MODES } from "../../constants/investigation";
import type { AnalysisMode } from "../../types/investigation";

export function InvestigationModeSelector({ mode, onChange, disabled }: { mode: AnalysisMode; onChange: (mode: AnalysisMode) => void; disabled: boolean }) {
  return <div className="mode-switch" role="tablist" aria-label="Investigation type">
    {INVESTIGATION_MODE_ORDER.map((id) => {
      const config = INVESTIGATION_MODES[id];
      return <button key={id} type="button" role="tab" aria-selected={mode === id} disabled={disabled} className={mode === id ? "is-active" : ""} onClick={() => onChange(id)}>
        {config.icon === "url" ? <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.2 2.3 3.3 5.1 3.3 8.5s-1.1 6.2-3.3 8.5c-2.2-2.3-3.3-5.1-3.3-8.5S9.8 5.8 12 3.5Z" /></svg> : config.icon === "message" ? <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3" /><path d="m4 7 8 6 8-6" /></svg> : <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3h7l5 5v13H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" /><path d="M14 3v6h5M9 14h6M9 17h6" /></svg>}
        <span>{config.label}</span><small>{config.description}</small>
      </button>;
    })}
  </div>;
}
