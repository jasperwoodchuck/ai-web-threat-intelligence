import { useRef, useState, type FormEvent } from "react";
import { analysisApiBaseUrl, apiUrl, isProductionApiConfigured } from "../lib/api";
import { parseTyposquattingDetection, type TyposquattingDisplay } from "../lib/typosquatting";
import type {
  AnalysisMode,
  AIExplanation,
  FileAnalysisResponse,
  MessageAnalysisResponse,
  UrlAnalysisResponse,
  WebsiteAvailability,
} from "../types/investigation";

// Allow the backend's bounded OpenRouter request and response processing to finish.
const ANALYSIS_TIMEOUT_MS = 120_000;

class AnalysisClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnalysisClientError";
  }
}

function isDevelopment() {
  return import.meta.env.DEV;
}

function analysisLog(message: string, details?: Record<string, unknown>) {
  if (isDevelopment()) console.debug(`[analysis] ${message}`, details ?? "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isAIExplanation(value: unknown): value is AIExplanation {
  return (
    isRecord(value) &&
    ["available", "unavailable", "malformed", "not_requested"].includes(String(value.status)) &&
    (typeof value.summary === "string" || value.summary === null) &&
    Array.isArray(value.suspicious_indicators) &&
    value.suspicious_indicators.every((item) => typeof item === "string") &&
    Array.isArray(value.evidence) &&
    value.evidence.every((item) => typeof item === "string") &&
    Array.isArray(value.recommended_actions) &&
    value.recommended_actions.every((item) => typeof item === "string") &&
    Array.isArray(value.limitations) &&
    value.limitations.every((item) => typeof item === "string") &&
    (value.confidence === null ||
      (typeof value.confidence === "number" &&
        Number.isFinite(value.confidence) &&
        value.confidence >= 0 &&
        value.confidence <= 1)) &&
    typeof value.advisory_note === "string"
  );
}

function responseDetail(payload: unknown): string | null {
  if (!isRecord(payload)) return null;
  if (typeof payload.detail === "string") return payload.detail;
  if (isRecord(payload.detail) && typeof payload.detail.message === "string")
    return payload.detail.message;
  return null;
}

function expectedResponse(
  payload: unknown,
  mode: AnalysisMode,
): payload is UrlAnalysisResponse | MessageAnalysisResponse | FileAnalysisResponse {
  if (!isRecord(payload)) return false;
  if (mode === "file") {
    return (
      typeof payload.filename === "string" &&
      typeof payload.media_type === "string" &&
      typeof payload.size_bytes === "number" &&
      typeof payload.sha256 === "string" &&
      typeof payload.extracted_text === "string" &&
      typeof payload.summary === "string" &&
      typeof payload.content_type === "string" &&
      typeof payload.classification_confidence === "number" &&
      typeof payload.classification_reasoning === "string" &&
      typeof payload.recommended_action === "string" &&
      Array.isArray(payload.key_findings) &&
      Array.isArray(payload.indicators) &&
      Array.isArray(payload.limitations) &&
      Array.isArray(payload.extracted_urls) &&
      Array.isArray(payload.deterministic_indicators) &&
      Array.isArray(payload.url_threat_intelligence) &&
      Array.isArray(payload.url_assessments) &&
      isRecord(payload.risk_assessment) &&
      isAIExplanation(payload.ai_explanation)
    );
  }
  return mode === "url"
    ? isRecord(payload.url_analysis) &&
        isRecord(payload.threat_intelligence) &&
        (payload.ai_explanation === undefined || isAIExplanation(payload.ai_explanation))
    : isAIExplanation(payload.ai_explanation) && Array.isArray(payload.deterministic_indicators) && Array.isArray(payload.url_assessments);
}

async function readJsonResponse(response: Response): Promise<unknown> {
  const body = await response.text();
  if (!body.trim()) return null;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    if (!response.ok) return null;
    throw new AnalysisClientError("Analysis service returned an unexpected response.");
  }
}

function httpErrorMessage(status: number, payload: unknown): string {
  const detail = responseDetail(payload);
  if (isRecord(payload) && isRecord(payload.detail) && payload.detail.code === "model_capability") {
    return "The configured analysis model does not support this image format. Try another image or contact the service administrator.";
  }
  if (
    isRecord(payload) &&
    isRecord(payload.detail) &&
    payload.detail.code === "malformed_provider_response"
  ) {
    return "The analysis service returned an unexpected result. Try again with another file.";
  }
  if (status === 401 || status === 403)
    return "Analysis service rejected the request. Check production authorization configuration.";
  if (status === 404)
    return "Analysis endpoint was not found. Check the production API URL and deployment route.";
  if (status >= 500) return "Analysis service failed while processing the request.";
  return detail ?? `Analysis request failed (HTTP ${status}).`;
}

export function useInvestigation() {
  const [mode, setMode] = useState<AnalysisMode>("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState("");
  const [fileResult, setFileResult] = useState<FileAnalysisResponse | null>(null);
  const [messageResult, setMessageResult] = useState<MessageAnalysisResponse | null>(null);
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null);
  const [availability, setAvailability] = useState<WebsiteAvailability | null>(null);
  const [typosquattingOnly, setTyposquattingOnly] = useState<TyposquattingDisplay | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailedOpen, setDetailedOpen] = useState(false);
  const inFlightRef = useRef(false);

  function selectMode(nextMode: AnalysisMode) {
    if (inFlightRef.current) return;
    setMode(nextMode);
    setError("");
    setResult(null);
    setMessageResult(null);
    setFileResult(null);
    setAvailability(null);
    setTyposquattingOnly(null);
    setDetailedOpen(false);
  }

  async function analyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlightRef.current) return;

    setError("");
    setResult(null);
    setMessageResult(null);
    setFileResult(null);
    setAvailability(null);
    setTyposquattingOnly(null);
    setDetailedOpen(false);

    const content = (mode === "url" ? url : message).trim();
    if (mode === "file" && !file) {
      setFileError("Please select a file to analyze.");
      return;
    }
    if (mode !== "file" && !content) {
      setError(mode === "url" ? "Enter a URL to analyze." : "Paste a message to analyze.");
      return;
    }
    if (!isProductionApiConfigured) {
      setError(
        "Production API URL is not configured. Set VITE_API_BASE_URL and rebuild the frontend.",
      );
      return;
    }

    inFlightRef.current = true;
    setLoading(true);
    const controller = new AbortController();
    let timedOut = false;
    const timeoutId = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, ANALYSIS_TIMEOUT_MS);
    const endpoint = apiUrl(`/api/v1/analyze/${mode}`);

    analysisLog("started", { mode });
    try {
      analysisLog("request sent", {
        mode,
        endpoint: new URL(endpoint, window.location.origin).pathname,
      });
      const body =
        mode === "file"
          ? (() => {
              const form = new FormData();
              if (file) form.append("file", file);
              return form;
            })()
          : JSON.stringify(mode === "url" ? { url: content } : { message: content });
      const response = await fetch(endpoint, {
        method: "POST",
        ...(mode === "file" ? {} : { headers: { "Content-Type": "application/json" } }),
        body,
        signal: controller.signal,
      });
      analysisLog("response received", { mode, status: response.status, ok: response.ok });
      const payload = await readJsonResponse(response);
      analysisLog("response parsed", {
        mode,
        payloadType: isRecord(payload) ? "object" : typeof payload,
      });

      if (!response.ok) {
        throw new AnalysisClientError(httpErrorMessage(response.status, payload));
      }
      if (mode === "url" && isRecord(payload) && isRecord(payload.availability)) {
        const status = payload.availability.status;
        const typoDetection = parseTyposquattingDetection(payload.typosquatting);
        if (status === "not_found" && typoDetection) {
          setTyposquattingOnly(typoDetection);
          analysisLog("completed", { mode, status, result: "typosquatting_only" });
          return;
        }
        const lookalikeDetected = typoDetection !== null;
        if (["not_found", "unreachable", "error"].includes(String(status)) && !lookalikeDetected) {
          setAvailability(payload.availability as unknown as WebsiteAvailability);
          if (status === "error")
            setError("Website availability could not be determined. Please retry the analysis.");
          analysisLog("completed", { mode, status });
          return;
        }
      }
      if (!expectedResponse(payload, mode)) {
        throw new AnalysisClientError("Analysis service returned an unexpected response.");
      }

      if (mode === "url" && "url_analysis" in payload) setResult(payload);
      else if (
        mode === "message" &&
        "ai_explanation" in payload &&
        "deterministic_indicators" in payload &&
        !("filename" in payload)
      )
        setMessageResult(payload);
      else if (mode === "file" && "sha256" in payload) setFileResult(payload);
      else throw new AnalysisClientError("Analysis service returned an unexpected response.");
      analysisLog("completed", { mode, status: "success" });
    } catch (caughtError) {
      if (timedOut) {
        analysisLog("timeout", { mode, timeoutMs: ANALYSIS_TIMEOUT_MS });
        setError("Analysis request timed out.");
      } else if (caughtError instanceof AnalysisClientError) {
        analysisLog("failed", { mode, reason: caughtError.message });
        setError(caughtError.message);
      } else {
        analysisLog("failed", { mode, reason: "network or CORS failure" });
        setError(
          "Unable to reach the analysis service. Check the production API URL and CORS configuration.",
        );
      }
    } finally {
      window.clearTimeout(timeoutId);
      inFlightRef.current = false;
      setLoading(false);
    }
  }

  return {
    mode,
    selectMode,
    url,
    setUrl,
    message,
    setMessage,
    file,
    setFile,
    fileError,
    setFileError,
    fileResult,
    messageResult,
    result,
    availability,
    typosquattingOnly,
    error,
    loading,
    detailedOpen,
    setDetailedOpen,
    analyze,
    apiBaseUrl: analysisApiBaseUrl,
  };
}
