from io import BytesIO
import json

import pytest
from fastapi import HTTPException
from starlette.datastructures import Headers, UploadFile
from pypdf import PdfWriter

from app import main
from app.ai.openrouter import ModelCapabilityError, ModelResponseError, ProviderRateLimitError
from app.models.message import AIExplanation, MessageAnalysisRequest
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus


def _upload(name, content, media_type):
    return UploadFile(filename=name, file=BytesIO(content), headers=Headers({"content-type": media_type}))


def _model_result(**overrides):
    result = {
        "extracted_text": "Your account is suspended. Verify your password immediately at https://account-check.test/login",
        "content_type": "email",
        "classification_confidence": 0.91,
        "classification_reasoning": "Email-like layout and account verification language are visible.",
        "summary": "An account warning requests urgent credential verification.",
        "indicators": ["Urgent credential request"],
        "recommended_action": "Do not use the link; verify through the official site.",
        "limitations": [],
    }
    return result | overrides


def _intel(indicator, status=ThreatIntelStatus.NO_MATCH):
    return ThreatIntelResult(
        status=status,
        matched=False if status is ThreatIntelStatus.NO_MATCH else None,
        source="URLhaus",
        indicator=indicator,
        error="not configured" if status is ThreatIntelStatus.UNAVAILABLE else None,
    )


def test_image_file_classifies_and_reuses_message_security_analysis(monkeypatch) -> None:
    monkeypatch.setattr(main.ai_provider, "inspect_image", lambda *_: _model_result())
    monkeypatch.setattr(main.threat_intel_provider, "lookup", lambda indicator: _intel(indicator))
    body = json.loads(main.analyze_file(_upload("evidence.jpg", b"\xff\xd8\xffsample", "image/jpeg")).body)
    assert body["content_type"] == "email"
    assert body["classification_confidence"] == 0.91
    assert body["extracted_urls"] == ["https://account-check.test/login"]
    assert {item["category"] for item in body["deterministic_indicators"]} >= {"urgency", "credential_request"}
    assert body["risk_assessment"]["score"] > 0
    assert body["recommended_action"].startswith("Do not use the link")
    assert len(body["sha256"]) == 64


def test_text_document_uses_shared_ai_and_returns_typed_analysis(monkeypatch) -> None:
    monkeypatch.setattr(main.ai_provider, "inspect_text", lambda text: _model_result(extracted_text=text, content_type="document"))
    monkeypatch.setattr(main.threat_intel_provider, "lookup", lambda indicator: _intel(indicator, ThreatIntelStatus.UNAVAILABLE))
    body = json.loads(main.analyze_file(_upload("note.txt", b"Please review this document.", "text/plain")).body)
    assert body["content_type"] == "document"
    assert body["extracted_text"] == "Please review this document."
    assert body["ai_explanation"]["status"] == "available"
    assert "risk_assessment" in body


def test_scanned_pdf_is_reported_as_unknown_without_claiming_ocr(monkeypatch) -> None:
    buffer = BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.write(buffer)
    body = json.loads(main.analyze_file(_upload("scan.pdf", buffer.getvalue(), "application/pdf")).body)
    assert body["content_type"] == "unknown"
    assert body["classification_confidence"] == 0
    assert any("not OCR processed" in item for item in body["limitations"])
    assert body["ai_explanation"]["status"] == "not_requested"


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (ModelResponseError("required fields missing: summary"), "malformed"),
        (RuntimeError("provider unavailable"), "unavailable"),
    ],
)
def test_image_ai_failure_status_is_preserved_in_result(monkeypatch, failure, expected_status) -> None:
    def fail(*_args):
        raise failure

    monkeypatch.setattr(main.ai_provider, "inspect_image", fail)
    body = json.loads(main.analyze_file(_upload("evidence.jpg", b"\xff\xd8\xffsample", "image/jpeg")).body)
    assert body["ai_explanation"]["status"] == expected_status
    assert body["content_type"] == "unknown"
    assert body["extracted_text"] == ""


def test_rate_limited_image_returns_structured_unavailable_and_keeps_security_result(monkeypatch) -> None:
    def fail(*_args):
        raise ProviderRateLimitError("rate limited", status=429, retry_after="2", kind="rate_limited")
    monkeypatch.setattr(main.ai_provider, "inspect_image", fail)
    body = json.loads(main.analyze_file(_upload("evidence.jpg", b"\xff\xd8\xffsample", "image/jpeg")).body)
    assert body["ai_explanation"]["status"] == "unavailable"
    assert body["ai_explanation"]["summary"] is None
    assert body["ai_explanation"]["suspicious_indicators"] == []
    assert any("rate limited (HTTP 429)" in item for item in body["limitations"])
    assert body["risk_assessment"] is not None
    assert body["deterministic_indicators"] == []


def test_unsupported_and_oversized_files_return_useful_statuses() -> None:
    with pytest.raises(HTTPException) as unsupported:
        main.analyze_file(_upload("payload.exe", b"MZ", "application/octet-stream"))
    with pytest.raises(HTTPException) as oversized:
        main.analyze_file(_upload("large.txt", b"x" * (10 * 1024 * 1024 + 1), "text/plain"))
    assert unsupported.value.status_code == 415
    assert oversized.value.status_code == 413


def test_configured_model_capability_error_is_explicit(monkeypatch) -> None:
    def capability_failure(*_args):
        raise ModelCapabilityError("model rejected image")

    monkeypatch.setattr(main.ai_provider, "inspect_image", capability_failure)
    with pytest.raises(HTTPException) as response:
        main.analyze_file(_upload("evidence.png", b"\x89PNG\r\n\x1a\ncontent", "image/png"))
    assert response.value.status_code == 422
    assert response.value.detail["code"] == "model_capability"


def test_message_attachment_reference_is_a_deterministic_signal(monkeypatch) -> None:
    monkeypatch.setattr(main.ai_provider, "explain", lambda *_: AIExplanation(status="unavailable"))
    monkeypatch.setattr(main.threat_intel_provider, "lookup", lambda indicator: _intel(indicator, ThreatIntelStatus.UNAVAILABLE))
    result = main.message_analyzer.analyze("Open the attached file immediately.")
    assert any(item.category == "attachment_reference" for item in result["deterministic_indicators"])


def test_message_route_returns_normalized_security_inputs(monkeypatch) -> None:
    monkeypatch.setattr(main.ai_provider, "explain", lambda *_: AIExplanation(status="available", summary="Verify the sender."))
    result = main.analyze_message(MessageAnalysisRequest(message="Open the attached file immediately."))
    assert result.ai_explanation.status == "available"
    assert result.risk_assessment.score > 0
    assert any(item.category == "attachment_reference" for item in result.deterministic_indicators)
