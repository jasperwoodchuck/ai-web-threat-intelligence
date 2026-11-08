import type { FormEvent } from "react";
import { INVESTIGATION_MODES } from "../../constants/investigation";
import type { AnalysisMode } from "../../types/investigation";
import { AnalyzeButton } from "./AnalyzeButton";
import { InvestigationModeSelector } from "./InvestigationModeSelector";
import { MessageInput } from "./MessageInput";
import { UrlInput } from "./UrlInput";
import { FileUploadPanel } from "./FileUploadPanel";

interface InvestigationWorkspaceProps {
  mode: AnalysisMode; onModeChange: (mode: AnalysisMode) => void; url: string; onUrlChange: (value: string) => void;
  message: string; onMessageChange: (value: string) => void; loading: boolean; onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  file: File | null; onFileChange: (value: File | null) => void; fileError: string; onFileError: (value: string) => void;
}

export function InvestigationWorkspace(props: InvestigationWorkspaceProps) {
  const config = INVESTIGATION_MODES[props.mode];
  return <>
    <section className="hero-block"><div className="hero-copy"><h1>Investigate suspicious content</h1></div><div className="privacy-note"><span className="privacy-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3 19 6v5.1c0 4.1-2.7 7.1-7 8.9-4.3-1.8-7-4.8-7-8.9V6l7-3Z" /><path d="m8.7 12 2.1 2.1 4.7-4.7" /></svg></span><span><strong>Passive analysis</strong><br />No page scripts</span></div></section>
    <form className="analysis-card" onSubmit={props.onSubmit}><div className="analysis-atmosphere" aria-hidden="true"><svg viewBox="0 0 260 150" fill="none"><path className="atmosphere-edge" d="M24 104 82 69 134 93 195 42 239 63M82 69 91 27M134 93l31 32 30-83" /><path className="atmosphere-edge atmosphere-edge-muted" d="m24 104 12 23M195 42l35-19M134 93l-8-48" /><circle className="atmosphere-node atmosphere-node-cyan" cx="24" cy="104" r="3" /><circle className="atmosphere-node atmosphere-node-blue" cx="91" cy="27" r="3" /><circle className="atmosphere-node atmosphere-node-violet" cx="195" cy="42" r="3" /><circle className="atmosphere-node atmosphere-node-amber" cx="165" cy="125" r="3" /><circle className="atmosphere-core" cx="134" cy="93" r="13" /><path className="atmosphere-core-mark" d="M129 93h10M134 88v10" /></svg></div>
      <InvestigationModeSelector mode={props.mode} onChange={props.onModeChange} disabled={props.loading} />
      {props.mode === "file" ? <FileUploadPanel file={props.file} onChange={props.onFileChange} error={props.fileError} onError={props.onFileError} /> : <div className={`analysis-input ${props.mode === "message" ? "is-message" : "is-url"}`}><div className="input-label-row"><label htmlFor={props.mode === "url" ? "url-input" : "message-input"}>{config.inputLabel}</label><span className="input-mode-note">{config.label} mode</span></div>
        {props.mode === "url" ? <UrlInput value={props.url} placeholder={config.placeholder} onChange={props.onUrlChange} /> : <MessageInput value={props.message} maxLength={config.maxLength ?? 20000} placeholder={config.placeholder} onChange={props.onMessageChange} />}
        <div className="analysis-supporting-text"><span>{config.supportingText}</span><span>{config.capabilities}</span>{props.mode === "message" && <span>{props.message.length.toLocaleString()} / 20,000</span>}</div>
      </div>}
      <div className="analysis-actions"><span className="analysis-hint">Selected mode determines the analysis that runs.</span><AnalyzeButton loading={props.loading} mode={props.mode} /></div>
    </form>
  </>;
}
