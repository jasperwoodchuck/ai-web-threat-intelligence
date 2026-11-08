import { expect, test } from "bun:test";
import { createSanitizedReport, formatSanitizedSummary } from "../src/lib/reportExport";
import type { MessageAnalysisResponse } from "../src/types/investigation";

const messageResult: MessageAnalysisResponse = {
  extracted_urls: ["https://private.example/reset?token=secret"],
  extracted_email_addresses: ["person@example.test"],
  extracted_phone_numbers: [],
  deterministic_indicators: [
    {
      category: "credential_request",
      severity: "high",
      description: "Credential request",
      evidence: "Send password hunter2 to person@example.test",
    },
  ],
  url_threat_intelligence: [
    {
      status: "no_match",
      matched: false,
      source: "URLhaus",
      indicator: "https://private.example/reset?token=secret",
      match_scope: "url",
      threat_type: null,
      confidence: null,
      evidence: {},
      reference: null,
      checked_at: "2026-11-08T00:00:00Z",
      error: null,
    },
  ],
  risk_assessment: {
    classification: "Suspicious",
    score: 52,
    confidence: 0.8,
    contributing_indicators: [
      {
        source: "message_analysis",
        indicator: "credential_request",
        severity: "high",
        weight: 20,
        description: "Credential request",
        evidence: "Send password hunter2 to person@example.test",
      },
    ],
    recommended_precautions: ["Verify the sender through an independent channel."],
    limitations: [],
  },
  ai_explanation: {
    status: "available",
    summary: "The message included hunter2 and a private reset link.",
    suspicious_indicators: [],
    evidence: [],
    recommended_actions: [],
    limitations: [],
    confidence: 0.8,
    advisory_note: "Advisory only.",
  },
  limitations: [],
};

test("sanitized export keeps assessment metadata and omits submitted content", () => {
  const report = createSanitizedReport(messageResult, new Date("2026-11-08T12:00:00.000Z"));
  const serialized = JSON.stringify(report);
  const summary = formatSanitizedSummary(report);

  expect(report.exported_at).toBe("2026-11-08T12:00:00.000Z");
  expect(report.analysis_type).toBe("message");
  expect(report.risk.score).toBe(52);
  expect(report.evidence_sources).toEqual(["URLhaus", "message_analysis"]);
  expect(serialized).not.toContain("private.example");
  expect(serialized).not.toContain("hunter2");
  expect(serialized).not.toContain("person@example.test");
  expect(summary).toContain("Verdict: Suspicious");
  expect(summary).toContain("Evidence sources: URLhaus, message_analysis");
  expect(summary).not.toContain("private.example");
  expect(summary).not.toContain("hunter2");
});
