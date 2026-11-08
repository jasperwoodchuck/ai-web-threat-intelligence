from typing import Literal

from pydantic import BaseModel, Field

from app.models.message import AIExplanation, MessageIndicator, MessageURLAssessment
from app.models.risk import RiskAssessment
from app.threat_intel.base import ThreatIntelResult

FileContentType = Literal[
    "email", "text_message", "chat_message", "notification",
    "website_screenshot", "login_security_page", "document",
    "image_with_text", "unknown",
]


class FileAnalysisResponse(BaseModel):
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    extracted_text: str = ""
    content_type: FileContentType = "unknown"
    classification_confidence: float = Field(default=0, ge=0, le=1)
    classification_reasoning: str = ""
    summary: str = ""
    key_findings: list[str] = Field(default_factory=list)
    recommended_action: str = "Review the extracted evidence before acting."
    indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    deterministic_indicators: list[MessageIndicator] = Field(default_factory=list)
    url_threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    url_assessments: list[MessageURLAssessment] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    ai_explanation: AIExplanation
