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

## License

This project is dual-licensed under either the MIT License or the Apache License, Version 2.0, at your option.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
