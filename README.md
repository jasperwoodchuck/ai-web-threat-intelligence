<div align="center">

<h1>Web Threat Intelligence</h1>

<p>Inspect URLs, suspicious messages, and files; review the checks and evidence behind each result.</p>

<p>
  <img src="https://shieldcn.dev/badge/Python-3.14%2B-3776AB.svg?logo=python&logoColor=white&variant=secondary&size=sm&radius=0" alt="Python 3.14 or newer">
  <img src="https://shieldcn.dev/badge/FastAPI.svg?color=009688&logo=fastapi&logoColor=white&variant=secondary&size=sm&radius=0" alt="FastAPI">
  <img src="https://shieldcn.dev/badge/React-19-61DAFB.svg?logo=react&logoColor=black&variant=secondary&size=sm&radius=0" alt="React 19">
  <img src="https://shieldcn.dev/badge/TypeScript-7-3178C6.svg?logo=typescript&logoColor=white&variant=secondary&size=sm&radius=0" alt="TypeScript 7">
  <img src="https://shieldcn.dev/badge/Deploy-Render-46E3B7.svg?logo=render&logoColor=black&variant=secondary&size=sm&radius=0" alt="Render configuration">
  <img src="https://shieldcn.dev/badge/License-MIT%20%2F%20Apache--2.0-blue.svg?variant=secondary&size=sm&radius=0" alt="MIT or Apache 2.0 license">
</p>

</div>

## What it does

| Area | Checks and output |
|---|---|
| 🌐 Website | URL parsing, reachability, DNS, TLS, HTTP headers, redirect response, URL heuristics, and URLhaus lookup. |
| 🔎 Message | Extracts links, email addresses, and phone numbers; flags patterns such as urgency, credential/payment requests, impersonation, and attachment references. |
| 📄 File | Accepts JPEG, PNG, WebP, PDF, and TXT up to 10 MB. Images use the configured model for OCR and visual analysis; PDFs and text files use text extraction. |
| 🤖 AI | Optional OpenRouter interpretation for text analysis. Image OCR/classification uses the configured OpenRouter model. |

Results include a risk score, findings, supporting evidence, and limitations. The score is an evidence aggregate, not a probability. AI output is advisory.

## Quick start

Requires Python 3.14+, `uv`, Bun, and `make`.

```bash
git clone https://github.com/jasperwoodchuck/ai-web-threat-intelligence.git
cd ai-web-threat-intelligence
make install
cp backend/.env.example backend/.env
make dev
```

Vite serves the frontend on port 5173 and proxies `/api` to FastAPI on port 8000. Set provider keys in `backend/.env` to enable URLhaus and OpenRouter lookups. The frontend's `VITE_API_BASE_URL` stays blank for local development.

## Configuration

| Variable | Purpose |
|---|---|
| `FRONTEND_ORIGIN` | Comma-separated browser origins allowed by backend CORS. |
| `URLHAUS_API_KEY` | Optional URLhaus key; without it, reputation lookups are unavailable. |
| `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` | Shared OpenRouter credentials and model for text interpretation and file analysis. Image analysis requires image-input support. |
| `VITE_API_BASE_URL` | Frontend build-time API origin; leave blank when using Vite's local proxy. |

Keep provider keys in the backend environment. `VITE_*` values are included in the built frontend.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Render health check |
| `POST` | `/api/v1/analyze/url` | Analyze a URL (`{"url":"https://example.com"}`) |
| `POST` | `/api/v1/analyze/message` | Analyze a message (`{"message":"..."}`, max 20,000 characters) |
| `POST` | `/api/v1/analyze/file` | Analyze a multipart `file` upload (max 10 MB) |

Interactive API docs are available at `/docs` while the backend is running. `/health` is also provided for the backend's best-effort keep-alive request.

## Development

```bash
make test        # Backend pytest suite
make lint        # Frontend Oxlint
make build       # TypeScript check and frontend production build
cd frontend && bun test
```

<div align="center">

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

</div>
