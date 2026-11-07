# Threat intelligence

The URL investigation can query the official [URLhaus Community API](https://urlhaus-api.abuse.ch/)
for an exact normalized URL match or a parsed hostname. URLhaus reports malware-distribution
URLs; its coverage is not exhaustive and does not represent a general safety verdict. A missing
match does not mean a URL is safe. A hostname association is distinguished from an exact URL
match; only an exact URL match can currently produce the `Confirmed Malicious` classification.

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
