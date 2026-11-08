import { useState, type FormEvent } from "react";
import { apiUrl } from "../lib/api";
import type { AnalysisMode, MessageAnalysisResponse, UrlAnalysisResponse } from "../types/investigation";

export function useInvestigation() {
  const [mode, setMode] = useState<AnalysisMode>("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [messageResult, setMessageResult] = useState<MessageAnalysisResponse | null>(null);
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailedOpen, setDetailedOpen] = useState(false);
  const [riskEvidenceOpen, setRiskEvidenceOpen] = useState(false);

  function selectMode(nextMode: AnalysisMode) {
    if (loading) return;
    setMode(nextMode);
    setError("");
    setResult(null);
    setMessageResult(null);
  }

  async function analyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);
    setMessageResult(null);
    setDetailedOpen(false);
    setRiskEvidenceOpen(false);

    const content = (mode === "url" ? url : message).trim();
    if (!content) {
      setError(mode === "url" ? "Enter a URL to analyze." : "Paste a message to analyze.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(apiUrl(`/api/v1/analyze/${mode}`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mode === "url" ? { url: content } : { message: content }),
      });
      const payload: unknown = await response.json();
      if (!response.ok) {
        const detail = typeof payload === "object" && payload !== null && "detail" in payload ? payload.detail : null;
        setError(typeof detail === "string" ? detail : `Analysis failed (${response.status}).`);
        return;
      }
      if (mode === "url") setResult(payload as UrlAnalysisResponse);
      else setMessageResult(payload as MessageAnalysisResponse);
    } catch {
      setError("Could not reach the analysis service.");
    } finally {
      setLoading(false);
    }
  }

  return {
    mode, selectMode, url, setUrl, message, setMessage, messageResult, result, error, loading,
    detailedOpen, setDetailedOpen, riskEvidenceOpen, setRiskEvidenceOpen, analyze,
  };
}
