import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnalysisResult } from "../src/components/results/AnalysisResult";

const messageResult = {
  extracted_urls: [],
  extracted_email_addresses: [],
  extracted_phone_numbers: [],
  deterministic_indicators: [],
  url_threat_intelligence: [],
  risk_assessment: {
    classification: "Inconclusive",
    score: 0,
    confidence: 0.35,
    contributing_indicators: [],
    recommended_precautions: [],
    limitations: [],
  },
  ai_explanation: {
    status: "available",
    summary: "The message uses urgency to request account verification.",
    suspicious_indicators: ["Urgent verification request"],
    evidence: ["The message asks the recipient to act immediately."],
    recommended_actions: ["Verify the sender through an official channel."],
    limitations: [],
    confidence: 0.82,
    advisory_note: "AI interpretation is advisory and is not verified threat intelligence.",
  },
  limitations: [],
};

test("successful API AI interpretation reaches the overview card and exposes a detail action", () => {
  const markup = renderToStaticMarkup(
    createElement(AnalysisResult, {
      result: messageResult,
      detailedOpen: false,
      onDetailedToggle: () => {},
    }),
  );

  expect(markup).toContain("AI overview");
  expect(markup).toContain("Available</span>");
  expect(markup).toContain("The message uses urgency to request account verification.");
  expect(markup).toContain("Urgent verification request");
  expect(markup).toContain('<button class="ai-overview-card ai-overview-trigger"');
  expect(markup).toContain('aria-label="AI interpretation: Available. View analysis details."');
});

test("malformed AI output is distinguished from provider unavailability", () => {
  const malformedResult = {
    ...messageResult,
    ai_explanation: {
      ...messageResult.ai_explanation,
      status: "malformed",
      summary: null,
      limitations: ["OpenRouter response could not be validated: required fields missing: summary."],
    },
  };
  const markup = renderToStaticMarkup(
    createElement(AnalysisResult, {
      result: malformedResult,
      detailedOpen: false,
      onDetailedToggle: () => {},
    }),
  );

  expect(markup).toContain("Malformed");
  expect(markup).toContain("did not match the expected schema");
  expect(markup).toContain('aria-label="AI interpretation: Malformed. View analysis details."');
});

test("rate limited interpretation shows an explicit unavailable overview", () => {
  const limitedResult = {
    ...messageResult,
    ai_explanation: {
      ...messageResult.ai_explanation,
      status: "unavailable",
      summary: null,
      suspicious_indicators: [],
      evidence: [],
      recommended_actions: [],
      limitations: ["OpenRouter interpretation is temporarily unavailable due to rate limiting (HTTP 429); deterministic analysis is preserved."],
      confidence: null,
    },
  };
  const markup = renderToStaticMarkup(
    createElement(AnalysisResult, {
      result: limitedResult,
      detailedOpen: false,
      onDetailedToggle: () => {},
    }),
  );
  expect(markup).toContain("AI overview");
  expect(markup).toContain("Unavailable</span>");
  expect(markup).toContain("temporarily unavailable because the provider is rate limited");
  expect(markup).toContain("Review the deterministic analysis below.");
});

test("rate-limited image analysis is shown as unavailable in the file result", () => {
  const fileResult = {
    filename: "evidence.png", media_type: "image/png", size_bytes: 12, sha256: "a".repeat(64),
    extracted_text: "", content_type: "unknown", classification_confidence: 0,
    classification_reasoning: "", summary: "Image analysis is unavailable.", key_findings: [],
    recommended_action: "Review the image manually.", indicators: [],
    limitations: ["OpenRouter image analysis was rate limited (HTTP 429); OCR and visual analysis are unavailable."],
    extracted_urls: [], deterministic_indicators: [], url_threat_intelligence: [],
    risk_assessment: {
      classification: "Inconclusive", score: 0, confidence: 0.35,
      contributing_indicators: [], recommended_precautions: [], limitations: [],
    },
    ai_explanation: {
      status: "unavailable", summary: null, suspicious_indicators: [], evidence: [],
      recommended_actions: [], limitations: ["OpenRouter image analysis was rate limited (HTTP 429)."],
      confidence: null, advisory_note: "AI interpretation is advisory and is not verified threat intelligence.",
    },
  } as const;
  const markup = renderToStaticMarkup(
    createElement(AnalysisResult, { result: fileResult, detailedOpen: false, onDetailedToggle: () => {} }),
  );
  expect(markup).toContain("Unavailable</span>");
  expect(markup).toContain("AI overview is temporarily unavailable because the provider is rate limited.");
  expect(markup).toContain("AI overview: Unavailable");
});
