from fastapi import FastAPI, HTTPException

from app.analyzers.dns import DnsAnalyzer
from app.analyzers.phishing import PhishingAnalyzer
from app.analyzers.tls import TlsAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.analysis import UrlAnalysisResponse
from app.models.url import UrlAnalysisRequest
from app.scoring.risk import RiskScorer

app = FastAPI(title="Web Threat Intelligence API")
url_analyzer = UrlAnalyzer()
dns_analyzer = DnsAnalyzer()
phishing_analyzer = PhishingAnalyzer()
tls_analyzer = TlsAnalyzer()
risk_scorer = RiskScorer()


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
    risk_assessment = risk_scorer.assess(
        url_analysis,
        dns_analysis,
        phishing_analysis,
        tls_analysis,
    )
    return UrlAnalysisResponse(
        url_analysis=url_analysis,
        dns_analysis=dns_analysis,
        phishing_analysis=phishing_analysis,
        risk_assessment=risk_assessment,
        tls_analysis=tls_analysis,
    )
