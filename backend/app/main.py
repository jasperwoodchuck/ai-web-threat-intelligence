import asyncio
import hashlib
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.ai.openrouter import ModelCapabilityError, ModelResponseError, OpenRouterProvider
from app.analyzers.dns import DnsAnalyzer
from app.analyzers.http import HttpAnalyzer
from app.analyzers.message import MAX_MESSAGE_LENGTH, MessageAnalyzer
from app.analyzers.phishing import PhishingAnalyzer
from app.analyzers.reachability import UrlReachabilityChecker
from app.analyzers.tls import TlsAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.config import frontend_origins, load_environment
from app.models.analysis import UrlAnalysisResponse, UrlAvailabilityResponse, WebsiteAvailability
from app.models.file import FileAnalysisResponse
from app.models.message import AIExplanation, MessageAnalysisRequest, MessageAnalysisResponse
from app.models.url import UrlAnalysisRequest
from app.scoring.risk import RiskScorer
from app.services.message_analysis import analyze_message_content
from app.threat_intel.urlhaus import UrlhausProvider
from pypdf import PdfReader
from io import BytesIO

load_environment()

logger = logging.getLogger(__name__)
# This public URL sends each ping back through Render's ingress. Render documents
# spin-down in terms of inbound traffic, but does not explicitly guarantee that
# service-originated requests reset the idle timer; this remains best-effort.
KEEP_ALIVE_URL = "https://ai-web-threat-intelligence-backend.onrender.com/health"
KEEP_ALIVE_INTERVAL_SECONDS = 10 * 60


async def _keep_service_warm() -> None:
    """Best-effort public-ingress request; Render does not guarantee self-pings prevent spin-down."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        while True:
            await asyncio.sleep(KEEP_ALIVE_INTERVAL_SECONDS)
            try:
                response = await client.get(KEEP_ALIVE_URL)
                response.raise_for_status()
                logger.info("Render keep-alive ping succeeded (status=%s)", response.status_code)
            except httpx.HTTPError as exc:
                logger.warning("Render keep-alive ping failed (%s)", type(exc).__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    keep_alive_task = asyncio.create_task(_keep_service_warm(), name="render-keep-alive")
    try:
        yield
    finally:
        keep_alive_task.cancel()
        try:
            await keep_alive_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Web Threat Intelligence API", lifespan=lifespan)
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
reachability_checker = UrlReachabilityChecker()
risk_scorer = RiskScorer()
threat_intel_provider = UrlhausProvider()
message_analyzer = MessageAnalyzer()
ai_provider = OpenRouterProvider()


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
def public_health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze/url", response_model=UrlAnalysisResponse | UrlAvailabilityResponse)
def analyze_url(request: UrlAnalysisRequest) -> UrlAnalysisResponse | UrlAvailabilityResponse:
    url_analysis = url_analyzer.analyze(request.url)
    if not url_analysis.is_valid:
        raise HTTPException(status_code=422, detail=url_analysis.validation_error)
    if url_analysis.hostname is None:
        raise HTTPException(status_code=422, detail="URL must include a hostname.")

    reachability = reachability_checker.check(
        url_analysis.normalized_url or request.url, url_analysis.hostname
    )
    availability = WebsiteAvailability(
        status=reachability.status, message=reachability.message,
        details=reachability.details, domain=url_analysis.hostname,
        http_status=reachability.http_status,
    )
    if reachability.status != "reachable":
        return UrlAvailabilityResponse(availability=availability)

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
        availability=availability,
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
    outcome = analyze_message_content(
        message,
        message_analyzer=message_analyzer,
        url_analyzer=url_analyzer,
        threat_intel_provider=threat_intel_provider,
        ai_provider=ai_provider,
        risk_scorer=risk_scorer,
    )
    return MessageAnalysisResponse(**outcome["analysis"], **{key: value for key, value in outcome.items() if key != "analysis"})


@app.post("/api/v1/analyze/file", response_model=FileAnalysisResponse)
def analyze_file(file: UploadFile = File(...)) -> FileAnalysisResponse | JSONResponse:
    allowed = {
        ".jpg": ("image/jpeg", "image/jpeg"), ".jpeg": ("image/jpeg", "image/jpeg"),
        ".png": ("image/png", "image/png"), ".webp": ("image/webp", "image/webp"),
        ".pdf": ("application/pdf", "application/pdf"), ".txt": ("text/plain", "text/plain"),
    }
    name = (file.filename or "upload").replace("\\", "_").replace("/", "_")[:180]
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    expected = allowed.get(suffix)
    if expected is None:
        raise HTTPException(status_code=415, detail="This file type isn't supported.")
    data = file.file.read(10 * 1024 * 1024 + 1)
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="The file is too large. Maximum size is 10 MB.")
    media_type, signature = expected
    valid = (
        (signature == "image/jpeg" and data.startswith(b"\xff\xd8\xff")) or
        (signature == "image/png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or
        (signature == "image/webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP") or
        (signature == "application/pdf" and data.startswith(b"%PDF-")) or
        (signature == "text/plain" and b"\x00" not in data)
    )
    if not valid or not data:
        raise HTTPException(status_code=400, detail="Unable to read this file. Try another file.")
    if file.content_type and file.content_type != media_type:
        raise HTTPException(status_code=415, detail="The file type does not match its contents.")
    extracted_text = ""
    limitations: list[str] = []
    ai_result: dict[str, object] = {}
    ai_explanation: AIExplanation | None = None
    if media_type.startswith("image/"):
        try:
            ai_result = ai_provider.inspect_image(data, media_type)
            extracted_text = str(ai_result.get("extracted_text", ""))
            ai_explanation = AIExplanation(
                status="available",
                summary=str(ai_result.get("summary", "")),
                suspicious_indicators=[str(item) for item in ai_result.get("indicators", [])],
                evidence=[str(ai_result.get("classification_reasoning", ""))] if ai_result.get("classification_reasoning") else [],
                recommended_actions=[str(ai_result.get("recommended_action", "Review the evidence before acting."))],
                limitations=[str(item) for item in ai_result.get("limitations", [])],
                confidence=float(ai_result.get("classification_confidence", 0)),
            )
        except ModelCapabilityError as exc:
            raise HTTPException(status_code=422, detail={"code": "model_capability", "message": "The configured analysis model does not support image input."}) from exc
        except ModelResponseError as exc:
            raise HTTPException(status_code=502, detail={"code": "malformed_provider_response", "message": "The analysis service returned an unreadable result. Please retry with a different file."}) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail={"code": "provider_failure", "message": "Image analysis is temporarily unavailable."}) from exc
    elif media_type == "text/plain":
        try:
            extracted_text = data.decode("utf-8-sig")[:30_000]
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Unable to read this text file.") from exc
        if not extracted_text.strip():
            raise HTTPException(status_code=400, detail="The text file contains no readable content.")
        try:
            ai_result = ai_provider.inspect_text(extracted_text)
            ai_explanation = AIExplanation(
                status="available", summary=str(ai_result.get("summary", "")),
                suspicious_indicators=[str(item) for item in ai_result.get("indicators", [])],
                evidence=[str(ai_result.get("classification_reasoning", ""))] if ai_result.get("classification_reasoning") else [],
                recommended_actions=[str(ai_result.get("recommended_action", "Review the evidence before acting."))],
                limitations=[str(item) for item in ai_result.get("limitations", [])],
                confidence=float(ai_result.get("classification_confidence", 0)),
            )
        except Exception:
            ai_result = {"content_type": "unknown", "classification_confidence": 0.35,
                         "classification_reasoning": "The file is plain text; model classification was unavailable.",
                         "summary": "Text was extracted. AI interpretation is currently unavailable.",
                         "indicators": [], "recommended_action": "Review the extracted text and verify links or requests independently."}
            ai_explanation = AIExplanation(status="unavailable", limitations=["AI file interpretation was unavailable; deterministic checks are shown."])
    else:
        try:
            reader = PdfReader(BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise ValueError("Encrypted PDF")
            if len(reader.pages) > 30:
                limitations.append("Only the first 30 PDF pages are considered.")
            extracted_text = "\n\n".join((page.extract_text() or "") for page in reader.pages[:30])[:30_000]
            if not extracted_text.strip():
                limitations.append("No selectable text was found. Scanned PDF pages are not OCR processed.")
                ai_result = {
                    "content_type": "unknown", "classification_confidence": 0,
                    "classification_reasoning": "The PDF contains no extractable text.",
                    "summary": "The PDF was validated, but no selectable text was available to analyze.",
                    "indicators": [], "recommended_action": "Review the PDF manually or upload page images for OCR.",
                }
            else:
                ai_result = {}
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Unable to read this PDF. Try another file.") from exc
        if extracted_text.strip():
            try:
                ai_result = ai_provider.inspect_text(extracted_text)
                ai_explanation = AIExplanation(
                    status="available", summary=str(ai_result.get("summary", "")),
                    suspicious_indicators=[str(item) for item in ai_result.get("indicators", [])],
                    evidence=[str(ai_result.get("classification_reasoning", ""))] if ai_result.get("classification_reasoning") else [],
                    recommended_actions=[str(ai_result.get("recommended_action", "Review the evidence before acting."))],
                    limitations=[str(item) for item in ai_result.get("limitations", [])],
                    confidence=float(ai_result.get("classification_confidence", 0)),
                )
            except Exception:
                ai_result = {"content_type": "unknown", "classification_confidence": 0.35,
                             "classification_reasoning": "Selectable PDF text was extracted; model classification was unavailable.",
                             "summary": "PDF text was extracted. AI interpretation is currently unavailable.",
                             "indicators": [], "recommended_action": "Review the extracted text and verify links or requests independently."}
                ai_explanation = AIExplanation(status="unavailable", limitations=["AI file interpretation was unavailable; deterministic checks are shown."])

    if media_type.startswith("image/"):
        limitations.append("Image OCR and visual interpretation are advisory and may omit or misread content.")
    if not extracted_text.strip():
        # Image interpretation may still provide useful visual analysis without OCR text.
        limitations.append("No text was extracted; message-pattern analysis is limited to visual model observations.")

    if ai_explanation is None:
        ai_explanation = AIExplanation(status="unavailable", limitations=["AI file interpretation was unavailable; deterministic checks are shown."])
    text_outcome = analyze_message_content(
        extracted_text,
        message_analyzer=message_analyzer,
        url_analyzer=url_analyzer,
        threat_intel_provider=threat_intel_provider,
        ai_provider=ai_provider,
        risk_scorer=risk_scorer,
        ai_explanation=ai_explanation,
    )
    analysis = text_outcome["analysis"]
    ai_explanation = text_outcome["ai_explanation"]
    indicators = [str(item) for item in ai_result.get("indicators", [])]
    key_findings = list(dict.fromkeys(
        [item.description for item in analysis["deterministic_indicators"]]
        + indicators
        + [item.description for item in text_outcome["url_threat_intelligence"] if item.status.value == "matched"]
    ))[:4]
    if not key_findings:
        key_findings = ["No supported security indicators were identified in the extracted content."]
    file_result = FileAnalysisResponse(
        filename=name,
        media_type=media_type,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        extracted_text=extracted_text,
        content_type=ai_result.get("content_type", "unknown"),
        classification_confidence=float(ai_result.get("classification_confidence", 0)),
        classification_reasoning=str(ai_result.get("classification_reasoning", "")),
        summary=str(ai_result.get("summary", "File content was extracted for security review.")),
        key_findings=key_findings,
        recommended_action=(ai_explanation.recommended_actions[0] if ai_explanation.recommended_actions else text_outcome["risk_assessment"].recommended_precautions[0]),
        indicators=indicators,
        limitations=list(dict.fromkeys(list(text_outcome["limitations"]) + limitations + list(ai_explanation.limitations))),
        extracted_urls=analysis["extracted_urls"],
        deterministic_indicators=analysis["deterministic_indicators"],
        url_threat_intelligence=text_outcome["url_threat_intelligence"],
        risk_assessment=text_outcome["risk_assessment"],
        ai_explanation=ai_explanation,
    )
    return JSONResponse(content=file_result.model_dump(mode="json"))
