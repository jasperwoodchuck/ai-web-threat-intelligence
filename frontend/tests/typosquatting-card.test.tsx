import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { TyposquattingDetectionCard } from "../src/components/results/TyposquattingDetectionCard";
import type { AnalysisApiResult } from "../src/lib/reportExport";
import { getTyposquattingDetection } from "../src/lib/typosquatting";

function urlResult(detected: boolean): AnalysisApiResult {
  return {
    url_analysis: {} as never,
    availability: {} as never,
    dns_analysis: {} as never,
    phishing_analysis: {
      is_suspicious: detected,
      score: detected ? 35 : 0,
      indicators: [],
      fraudurl: {} as never,
      typosquatting: {
        type: "typosquatting",
        detected,
        submitted_domain: "paypa1.com",
        possible_intended_site: detected ? "paypal.com" : null,
        similarity: detected ? 0.92 : null,
        edit_distance: detected ? 1 : null,
        domain: "paypa1.com",
        reference_domain: detected ? "paypal.com" : null,
        technique: detected ? "character_substitution" : null,
        severity: detected ? "medium" : null,
        evidence: detected ? "The digit '1' is commonly used in place of the letter 'l'." : null,
        is_idn: false,
      },
    },
    typosquatting: {
      type: "typosquatting",
      detected,
      submitted_domain: "paypa1.com",
      possible_intended_site: detected ? "paypal.com" : null,
      similarity: detected ? 0.92 : null,
      edit_distance: detected ? 1 : null,
      domain: "paypa1.com",
      reference_domain: detected ? "paypal.com" : null,
      technique: detected ? "character_substitution" : null,
      severity: detected ? "medium" : null,
      evidence: detected ? "The digit '1' is commonly used in place of the letter 'l'." : null,
      is_idn: false,
    },
    risk_assessment: {} as never,
    tls_analysis: {} as never,
    http_analysis: {} as never,
    threat_intelligence: {} as never,
  };
}

test("a confirmed URL typo match produces the correction card using backend evidence", () => {
  const detection = getTyposquattingDetection(urlResult(true));
  expect(detection).not.toBeNull();
  if (!detection) return;

  const markup = renderToStaticMarkup(createElement(TyposquattingDetectionCard, { detection }));
  expect(markup).toContain("Did you mean paypal.com?");
  expect(markup).toContain("paypa1.com");
  expect(markup).toContain("Character Substitution");
  expect(markup).toContain("The digit &#x27;1&#x27;");
});

test("a URL without an explicit typo detection does not produce a card", () => {
  expect(getTyposquattingDetection(urlResult(false))).toBeNull();
  expect(getTyposquattingDetection({} as AnalysisApiResult)).toBeNull();
});
