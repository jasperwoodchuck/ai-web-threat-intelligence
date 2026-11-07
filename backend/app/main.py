from fastapi import FastAPI, HTTPException

from app.analyzers.url import UrlAnalyzer
from app.models.url import UrlAnalysisRequest, UrlAnalysisResult

app = FastAPI(title="Web Threat Intelligence API")
url_analyzer = UrlAnalyzer()


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze/url", response_model=UrlAnalysisResult)
def analyze_url(request: UrlAnalysisRequest) -> UrlAnalysisResult:
    result = url_analyzer.analyze(request.url)
    if not result.is_valid:
        raise HTTPException(status_code=422, detail=result.validation_error)
    return result
