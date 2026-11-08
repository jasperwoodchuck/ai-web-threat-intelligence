# Demo and test report

This is a short walkthrough for the current hackathon MVP. Provider-backed results depend on network access and configured API keys; AI summaries can vary. The cases below describe expected behavior and distinguish live checks from mocked regression tests.

## Demo setup

From the repository root:

```bash
make install
cp backend/.env.example backend/.env
# Add OPENROUTER_API_KEY and OPENROUTER_MODEL; URLHAUS_API_KEY is optional.
make dev
```

Use only public targets you are authorized to inspect, and synthetic message/file content. Do not use real credentials, personal messages, or confidential screenshots.

## Walkthrough

| Step                           | Input                                                                                                                                                                            | Expected behavior                                                                                                                                                                                                                                                     |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Website                        | `https://example.com`                                                                                                                                                            | Shows availability and the collected DNS, TLS, HTTP, URL-signal, and reputation results. URLhaus may be unavailable without its key. A no-match result does not establish that the site is safe. Network reachability and provider availability affect the result.    |
| Suspicious URL regression case | `https://yovtube.com` in the backend test fixture                                                                                                                                | The fixture mocks reachability and providers, then verifies the lookalike-domain signal for `youtube.com` reaches the risk result. This is a deterministic regression test, not a claim that the live domain is malicious.                                            |
| Message                        | `Your account is suspended. Verify your password immediately to avoid losing access.`                                                                                            | Deterministic checks should report urgency and credential-request language. AI interpretation is advisory and may be unavailable. The language alone should not confirm fraud.                                                                                        |
| Screenshot/file                | Make a screenshot containing fictional text such as `Your account is suspended. Verify your password immediately at https://example.invalid/login`, then upload it in File mode. | With a configured image-capable model, the app attempts OCR, content classification, link extraction, and shared message checks. Review the returned text and evidence. Classification and AI wording are model-dependent; low-confidence content may remain unknown. |
| Export                         | After any result, use **Copy summary** or **Download JSON**.                                                                                                                     | The export includes its export timestamp, verdict, score, confidence, check statuses, source names, and deterministic precautions. It omits submitted URLs, message text, filenames, file contents, OCR text, extracted indicators, and AI prose.                     |

## Existing automated coverage

The repository contains tests for URL heuristics and risk scoring, including a mocked end-to-end lookalike case; message indicators and reputation lookup; TLS and HTTP metadata checks; and file validation and analysis response handling. The image-analysis API test mocks the model response, so it verifies pipeline integration rather than OCR accuracy or live provider behavior. Scanned PDFs are currently reported without OCR.

Run the available checks from the repository root:

```bash
make test
make lint
make build
cd frontend && bun test
```

For the report-export change, `cd frontend && bun test` passes (3 tests, including a check that submitted URL, email, and message content are omitted), and `bun run build` completes successfully. The backend suite was not run for this frontend-only change.

## Current limits and follow-up

- Redirect responses are recorded but not followed, so the app does not report a full redirect chain.
- Certificate Transparency, revocation, and compromised-CA sources are not checked.
- URLhaus is the external reputation source; no match is not proof of safety.
- There is no persistent incident store, cross-submission campaign correlation, report-submission service, or blockchain verification.
- PDF text extraction does not OCR scanned pages.
- OpenRouter receives submitted message or image content when configured; its interpretation remains advisory.
- **URL availability probing needs SSRF hardening before exposing the scanner broadly.** The reachability probe requests the submitted hostname without pinning it to an address verified as public. Reject private/internal destinations and bind requests to validated public IPs before treating this as a public production scanner.

The export is generated locally in the browser and is not uploaded or stored by the application.
