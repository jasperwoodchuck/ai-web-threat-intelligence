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
    <section className="hero-block"><div className="hero-copy"><h1>Investigate suspicious content</h1></div></section>
    <form className="analysis-card" onSubmit={props.onSubmit}>
      <InvestigationModeSelector mode={props.mode} onChange={props.onModeChange} disabled={props.loading} />
      {props.mode === "file" ? <FileUploadPanel file={props.file} onChange={props.onFileChange} error={props.fileError} onError={props.onFileError} /> : <div className={`analysis-input ${props.mode === "message" ? "is-message" : "is-url"}`}><div className="input-label-row"><label htmlFor={props.mode === "url" ? "url-input" : "message-input"}>{config.inputLabel}</label><span className="input-mode-note">{config.label} mode</span></div>
        {props.mode === "url" ? <UrlInput value={props.url} placeholder={config.placeholder} onChange={props.onUrlChange} /> : <MessageInput value={props.message} maxLength={config.maxLength ?? 20000} placeholder={config.placeholder} onChange={props.onMessageChange} />}
        <div className="analysis-supporting-text"><span>{props.mode === "message" ? `${props.message.length.toLocaleString()} / 20,000` : config.supportingText}</span><span>{config.capabilities}</span></div>
      </div>}
      <div className="analysis-actions"><span className="analysis-hint">Selected mode determines the analysis that runs.</span><AnalyzeButton loading={props.loading} mode={props.mode} /></div>
    </form>
  </>;
}
