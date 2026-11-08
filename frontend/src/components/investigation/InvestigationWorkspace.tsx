import type { FormEvent } from "react";
import { INVESTIGATION_MODES } from "../../constants/investigation";
import type { AnalysisMode } from "../../types/investigation";
import { AnalyzeButton } from "./AnalyzeButton";
import { InvestigationModeSelector } from "./InvestigationModeSelector";
import { MessageInput } from "./MessageInput";
import { UrlInput } from "./UrlInput";

interface InvestigationWorkspaceProps {
  mode: AnalysisMode; onModeChange: (mode: AnalysisMode) => void; url: string; onUrlChange: (value: string) => void;
  message: string; onMessageChange: (value: string) => void; loading: boolean; onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

export function InvestigationWorkspace(props: InvestigationWorkspaceProps) {
  const config = INVESTIGATION_MODES[props.mode];
  return <>
    <section className="hero-block"><div className="hero-copy"><p className="eyebrow">SECURITY ANALYSIS WORKSPACE</p><h1>Investigate suspicious content</h1><p className="intro-copy">Analyze URLs and suspicious messages for security signals, reputation, and threat indicators.</p></div><div className="privacy-note"><span className="privacy-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3 19 6v5.1c0 4.1-2.7 7.1-7 8.9-4.3-1.8-7-4.8-7-8.9V6l7-3Z" /><path d="m8.7 12 2.1 2.1 4.7-4.7" /></svg></span><span><strong>Passive analysis</strong><br />No page scripts executed</span></div></section>
    <form className="analysis-card" onSubmit={props.onSubmit}><div className="analysis-card-heading"><div><p className="eyebrow">INVESTIGATION INPUT</p><h2>Choose what you want to investigate</h2></div><span className="analysis-step">01 <i /> 02 <i /> 03</span></div>
      <InvestigationModeSelector mode={props.mode} onChange={props.onModeChange} disabled={props.loading} />
      <div className={`analysis-input ${props.mode === "message" ? "is-message" : "is-url"}`}><div className="input-label-row"><label htmlFor={props.mode === "url" ? "url-input" : "message-input"}>{config.inputLabel}</label><span className="input-mode-note">{config.label} mode</span></div>
        {props.mode === "url" ? <UrlInput value={props.url} placeholder={config.placeholder} onChange={props.onUrlChange} /> : <MessageInput value={props.message} maxLength={config.maxLength ?? 20000} placeholder={config.placeholder} onChange={props.onMessageChange} />}
        <div className="analysis-supporting-text"><span>{config.supportingText}</span><span>{config.capabilities}</span>{props.mode === "message" && <span>{props.message.length.toLocaleString()} / 20,000</span>}</div>
      </div>
      <div className="analysis-actions"><span className="analysis-hint">Selected mode determines the analysis that runs.</span><AnalyzeButton loading={props.loading} /></div>
    </form>
  </>;
}
