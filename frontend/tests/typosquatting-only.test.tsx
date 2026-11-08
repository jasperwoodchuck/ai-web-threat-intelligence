import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { InvestigationResults } from "../src/components/results/InvestigationResults";

test("a detected typo on a DNS non-existent URL renders only the typo result card", () => {
  const markup = renderToStaticMarkup(
    createElement(InvestigationResults, {
      result: null,
      availability: null,
      typosquattingOnly: {
        domain: "yovtube.com",
        referenceDomain: "youtube.com",
        technique: "character_substitution",
        severity: "medium",
        evidence: "'v' replaces 'u' in the domain label.",
        similarity: 0.86,
      },
      fileResult: null,
      messageResult: null,
      error: "",
      loading: false,
      detailedOpen: false,
      setDetailedOpen: () => {},
    }),
  );

  expect(markup).toContain("Did you mean youtube.com?");
  expect(markup).toContain("yovtube.com");
  expect(markup).not.toContain("Website not found");
  expect(markup).not.toContain("AI overview");
  expect(markup).not.toContain("OVERALL VERDICT");
});
