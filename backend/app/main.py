from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.ai.openrouter import OpenRouterProvider
from app.analyzers.dns import DnsAnalyzer
from app.analyzers.http import HttpAnalyzer
from app.analyzers.message import MAX_MESSAGE_LENGTH, MessageAnalyzer
from app.analyzers.phishing import PhishingAnalyzer
from app.analyzers.tls import TlsAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.config import frontend_origins, load_environment
from app.models.analysis import UrlAnalysisResponse
from app.models.message import AIExplanation, MessageAnalysisRequest, MessageAnalysisResponse
from app.models.url import UrlAnalysisRequest
from app.scoring.risk import RiskScorer
from app.threat_intel.urlhaus import UrlhausProvider

load_environment()

app = FastAPI(title="Web Threat Intelligence API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
url_analyzer = UrlAnalyzer()
dns_analyzer = DnsAnalyzer()
phishing_analyzer = PhishingAnalyzer()
tls_analyzer = TlsAnalyzer()
http_analyzer = HttpAnalyzer()
risk_scorer = RiskScorer()
threat_intel_provider = UrlhausProvider()
message_analyzer = MessageAnalyzer()
ai_provider = OpenRouterProvider()


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze/url", response_model=UrlAnalysisResponse)
def analyze_url(request: UrlAnalysisRequest) -> UrlAnalysisResponse:
    url_analysis = url_analyzer.analyze(request.url)
    if not url_analysis.is_valid:
        raise HTTPException(status_code=422, detail=url_analysis.validation_error)
    if url_analysis.hostname is None:
        raise HTTPException(status_code=422, detail="URL must include a hostname.")

    dns_analysis = dns_analyzer.analyze(url_analysis.hostname)
    phishing_analysis = phishing_analyzer.analyze(url_analysis)
    tls_analysis = tls_analyzer.analyze(url_analysis, dns_analysis)
    http_analysis = http_analyzer.analyze(url_analysis, dns_analysis)
    threat_intelligence = threat_intel_provider.lookup(
        url_analysis.normalized_url or request.url
    )
    risk_assessment = risk_scorer.assess(
        url_analysis,
        dns_analysis,
        phishing_analysis,
        tls_analysis,
        threat_intelligence,
        http_analysis=http_analysis,
    )
    return UrlAnalysisResponse(
        url_analysis=url_analysis,
        dns_analysis=dns_analysis,
        phishing_analysis=phishing_analysis,
        typosquatting=phishing_analysis.typosquatting,
        risk_assessment=risk_assessment,
        tls_analysis=tls_analysis,
        http_analysis=http_analysis,
        threat_intelligence=threat_intelligence,
    )


@app.post("/api/v1/analyze/message", response_model=MessageAnalysisResponse)
def analyze_message(request: MessageAnalysisRequest) -> MessageAnalysisResponse:
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Message must not be empty or whitespace.")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise HTTPException(status_code=422, detail=f"Message must be at most {MAX_MESSAGE_LENGTH} characters.")
    analysis = message_analyzer.analyze(message)
    intel_results = []
    for extracted_url in analysis["extracted_urls"]:
        parsed = url_analyzer.analyze(extracted_url)
        if not parsed.is_valid or not parsed.normalized_url or not parsed.hostname:
            continue
        if parsed.has_query or parsed.has_username:
            # Avoid sending possibly sensitive query parameters or URL credentials
            # to a third party; retain only a hostname association in this case.
            intel_results.append(threat_intel_provider.lookup(parsed.hostname))
        else:
            exact = threat_intel_provider.lookup(parsed.normalized_url)
            intel_results.append(exact)
            if exact.status.value == "no_match":
                # Host association is a separate, weaker scope; never crawl the URL.
                intel_results.append(threat_intel_provider.lookup(parsed.hostname))
    indicator_payload = [item.model_dump(mode="json") for item in analysis["deterministic_indicators"]]
    intel_payload = [item.model_dump(mode="json") for item in intel_results]
    try:
        ai_explanation = ai_provider.explain(message, indicator_payload, intel_payload)
    except Exception:
        ai_explanation = AIExplanation(status="unavailable", limitations=["OpenRouter explanation failed; deterministic analysis is preserved."])
    risk = risk_scorer.assess_message(analysis["deterministic_indicators"], intel_results, ai_explanation)
    limitations = list(risk.limitations)
    if analysis["extracted_urls"]:
        limitations.append("Extracted URLs were normalized and checked against threat intelligence only; no website request or redirect following was performed.")
        if any(url_analyzer.analyze(url).has_query or url_analyzer.analyze(url).has_username for url in analysis["extracted_urls"]):
            limitations.append("URL queries and embedded credentials were not sent to threat intelligence; those URLs received hostname-only lookup.")
    else:
        limitations.append("No HTTP/HTTPS URLs were extracted for threat-intelligence lookup.")
    limitations.append("When enabled, the submitted message is sent to OpenRouter for advisory interpretation.")
    return MessageAnalysisResponse(**analysis, url_threat_intelligence=intel_results, risk_assessment=risk, ai_explanation=ai_explanation, limitations=list(dict.fromkeys(limitations)))
