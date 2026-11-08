import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Badge } from "../ui/Badge";

export type AnalysisCardDetail = {
  title: string;
  status: string;
  data: unknown;
  content?: ReactNode;
};

export function AnalysisDetailModal({
  detail,
  onClose,
}: {
  detail: AnalysisCardDetail | null;
  onClose: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const previousBodyOverflow = document.body.style.overflow;
    const previousRootOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
    dialog.showModal();

    return () => {
      if (dialog.open) dialog.close();
      document.body.style.overflow = previousBodyOverflow;
      document.documentElement.style.overflow = previousRootOverflow;
    };
  }, []);

  if (!detail) return null;

  const serialized =
    typeof detail.data === "string"
      ? detail.data
      : detail.data === undefined || detail.data === null
        ? ""
        : JSON.stringify(detail.data, null, 2);
  const content = serialized || "No additional details are available for this check.";

  return createPortal(
    <dialog
      ref={dialogRef}
      className="analysis-detail-dialog"
      aria-labelledby={titleId}
      aria-describedby={`${titleId}-status`}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <header className="analysis-detail-header">
        <div>
          <p className="eyebrow">ANALYSIS DETAILS</p>
          <h2 id={titleId}>{detail.title}</h2>
        </div>
        <button
          className="analysis-detail-close"
          type="button"
          aria-label="Close analysis details"
          autoFocus
          onClick={onClose}
        >
          <span aria-hidden="true">×</span>
        </button>
      </header>
      <div className="analysis-detail-status" id={`${titleId}-status`}>
        <span>Status</span>
        <Badge tone="info">{detail.status}</Badge>
      </div>
      <div className="analysis-detail-content" tabIndex={0}>
        {detail.content ? (
          detail.content
        ) : (
          <>
            <h3>{detail.title === "Text extraction" ? "Extracted text" : "Underlying data"}</h3>
            <pre>{content}</pre>
          </>
        )}
      </div>
    </dialog>,
    document.body,
  );
}
