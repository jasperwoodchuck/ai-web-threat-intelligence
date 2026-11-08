import { EmptyState } from "../ui/EmptyState";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import type {
  FileAnalysisResponse,
  MessageAnalysisResponse,
  UrlAnalysisResponse,
  WebsiteAvailability,
} from "../../types/investigation";
import { AnalysisResult } from "./AnalysisResult";

type InvestigationResultsProps = {
  result: UrlAnalysisResponse | null;
  availability: WebsiteAvailability | null;
  fileResult: FileAnalysisResponse | null;
  messageResult: MessageAnalysisResponse | null;
  error: string;
  loading: boolean;
  detailedOpen: boolean;
  setDetailedOpen: (open: boolean) => void;
};

export function InvestigationResults(props: InvestigationResultsProps) {
  const analysis = props.result ?? props.messageResult ?? props.fileResult;
  return (
    <>
      {props.availability && (
        <section
          className={`availability-card availability-${props.availability.status}`}
          role="status"
          aria-live="polite"
        >
          <div className="availability-icon" aria-hidden="true">
            {props.availability.status === "not_found" ? "?" : "!"}
          </div>
          <div className="availability-copy">
            <p className="eyebrow">WEBSITE AVAILABILITY</p>
            <h2>
              {props.availability.status === "not_found"
                ? "Website not found"
                : props.availability.status === "unreachable"
                  ? "Website unreachable"
                  : "Availability check failed"}
            </h2>
            <strong className="availability-domain">{props.availability.domain}</strong>
            <p>
              {props.availability.status === "not_found"
                ? "The domain could not be resolved. Check the URL and try again."
                : props.availability.status === "unreachable"
                  ? "The domain exists, but the server could not be reached. This does not by itself indicate that the website is malicious."
                  : "Website availability could not be determined. Retry the check."}
            </p>
            <p className="availability-detail">{props.availability.details}</p>
          </div>
        </section>
      )}
      {props.error && !props.availability && <ErrorState message={props.error} />}
      {props.loading && <LoadingState />}
      {analysis && !props.loading && (
        <AnalysisResult
          result={analysis}
          detailedOpen={props.detailedOpen}
          onDetailedToggle={props.setDetailedOpen}
        />
      )}
      {!analysis && !props.availability && !props.loading && !props.error && <EmptyState />}
    </>
  );
}
