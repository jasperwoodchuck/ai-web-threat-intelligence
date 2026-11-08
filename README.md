# Threat intelligence

The URL investigation can query the official [URLhaus Community API](https://urlhaus-api.abuse.ch/)
for an exact normalized URL match or a parsed hostname. URLhaus reports malware-distribution
URLs; its coverage is not exhaustive and does not represent a general safety verdict. A missing
match does not mean a URL is safe. A hostname association is distinguished from an exact URL
match; only an exact URL match can currently produce the `Confirmed Malicious` classification.

Risk scoring combines independent evidence groups with a bounded noisy-OR calculation.
For each signal strength `s` (0-100), the cumulative score becomes
`100 - (100 - current_score) * (1 - s / 100)`. Correlated signals in the same family
use diminishing factors (1, 0.35, 0.15, then 0.05) before combination. fraudurl
probability contributes proportionally above 0.5; values below 0.5 can reduce the score
by at most 10 points as limited counterevidence. An exact URLhaus match contributes a
base strength of 80 multiplied by provider confidence; a hostname association uses 50.
Only an exact URL match with a combined score of at least 70 is `Confirmed Malicious`.
Existing score bands remain: 1-14 Low Risk, 15-34 Suspicious, and 35+ High Risk; zero
is Inconclusive. `RiskEvidence.weight` is the signed marginal change to the final score,
so the evidence weights sum to that score. Analyzer errors, timeouts, and not-applicable
checks do not add risk points. Confidence measures analysis coverage and consistency,
not risk or probability of fraud.

Create an abuse.ch account for an API key, then configure the backend:

```bash
cd backend
cp .env.example .env
# Set URLHAUS_API_KEY in .env
```

Never commit the real `.env` file. The key is loaded by the backend, sent only to URLhaus, and
never returned to the frontend. If the key is absent, the provider remains unavailable. Timeouts,
rate limits, and invalid responses also produce an unavailable result; none of these count as a
no-match result.

For exact URL lookups, the backend removes URL credentials and fragments before sending the URL;
the path and query remain part of the exact indicator lookup.

## Message scam analysis

`POST /api/v1/analyze/message` accepts `{"message":"..."}` (up to 20,000 characters).
The deterministic analyzer extracts HTTP(S) URLs, email addresses, and phone numbers, and
records observable urgency, payment, credential/sensitive-information, impersonation, and
link/contact indicators. Extracted URLs are normalized and sent to URLhaus for exact URL lookup;
a no-match may be followed by a separate hostname association lookup. The service does not fetch
those websites or follow their redirects.

Configure optional advisory explanations in `backend/.env`:

```env
OPENROUTER_API_KEY=
OPENROUTER_MODEL=
```

The deterministic analysis and risk assessment work without OpenRouter. When configured, the
submitted message and separate deterministic evidence are sent to OpenRouter. The system prompt
marks message text as untrusted content and instructs the model to ignore embedded instructions.
AI output is structured, advisory interpretation; it cannot override threat-intelligence results
or establish `Confirmed Malicious`. Malformed or unavailable AI output does not discard
deterministic findings.

Urgent or persuasive wording is not proof of fraud. Similarly, no threat-intelligence match is
not proof that a message or URL is safe. Provider coverage is limited to URLhaus malware reports;
message language analysis is heuristic, and extracted email addresses and phone numbers are not
independently verified. Avoid submitting content you do not want shared with the configured AI
provider.

## License

This project is dual-licensed under either the MIT License or the Apache License, Version 2.0, at your option.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
