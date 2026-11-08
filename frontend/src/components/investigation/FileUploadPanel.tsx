import { useRef, useState } from "react";

const MAX_BYTES = 10 * 1024 * 1024;
const ACCEPTED_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "application/pdf", "text/plain"]);

export function FileUploadPanel({ file, onChange, error, onError }: { file: File | null; onChange: (file: File | null) => void; error: string; onError: (message: string) => void }) {
  const picker = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  function select(candidate?: File) {
    if (!candidate) return;
    if (!ACCEPTED_TYPES.has(candidate.type)) { onError("This file type isn't supported. Choose JPG, PNG, WEBP, PDF, or TXT."); return; }
    if (candidate.size > MAX_BYTES) { onError("The file is too large. Maximum size is 10 MB."); return; }
    onError(""); onChange(candidate);
  }
  const safeName = (file?.name ?? "").replace(/[\x00-\x1f<>:"/\\|?*]/g, "_").slice(0, 180);
  return <div className="analysis-input file-input-panel">
    <div className="input-label-row"><label>Upload or capture a file</label><span className="input-mode-note">Maximum 10 MB</span></div>
    <p className="file-intro">Add an image or document for OCR and security analysis.</p>
    <div className={`file-dropzone${dragging ? " is-dragging" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); select(event.dataTransfer.files[0]); }}>
      <input ref={picker} className="file-picker-input" type="file" accept="image/jpeg,image/png,image/webp,application/pdf,text/plain" onChange={(event) => select(event.currentTarget.files?.[0])} aria-label="Choose a file to analyze" />
      {!file ? <div className="file-empty"><span className="file-empty-icon" aria-hidden="true">⇧</span><strong>Drag &amp; drop file here</strong><span className="file-support">JPG · PNG · WEBP · PDF · TXT</span><div className="file-actions"><button type="button" className="file-action-button" onClick={() => { picker.current?.setAttribute("accept", "image/jpeg,image/png,image/webp,application/pdf,text/plain"); picker.current?.removeAttribute("capture"); picker.current?.click(); }}>Choose file</button><button type="button" className="file-action-button" onClick={() => { picker.current?.setAttribute("accept", "image/*"); picker.current?.setAttribute("capture", "environment"); picker.current?.click(); }}>Use camera</button></div></div> :
        <div className="file-preview"><span className="file-preview-icon" aria-hidden="true">{file.type.startsWith("image/") ? "IMG" : file.type === "application/pdf" ? "PDF" : "TXT"}</span><span className="file-metadata"><strong>{safeName}</strong><small>{file.type} · {(file.size / 1024 / 1024).toFixed(2)} MB</small></span><div className="file-actions"><button type="button" className="file-action-button" onClick={() => picker.current?.click()}>Replace</button><button type="button" className="file-remove" onClick={() => { onChange(null); onError(""); if (picker.current) picker.current.value = ""; }}>Remove</button></div></div>}
    </div>
    <p className="file-privacy">Files are processed for analysis. Only upload information you are authorized to share.</p>
    {error && <p className="file-error" role="alert">{error}</p>}
  </div>;
}
