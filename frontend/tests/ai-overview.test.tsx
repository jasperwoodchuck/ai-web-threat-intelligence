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

test("successful API AI interpretation reaches the overview card and its expanded details", () => {
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
  expect(markup).toContain("The message asks the recipient to act immediately.");
  expect(markup).toContain("Verify the sender through an official channel.");
  expect(markup).toContain('<details class="ai-overview-card">');
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
  expect(markup).toContain("required fields missing: summary");
});
