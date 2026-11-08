from typing import Literal

from pydantic import BaseModel, Field

from app.models.risk import RiskAssessment
from app.models.phishing import PhishingAnalysisResult
from app.threat_intel.base import ThreatIntelResult
from app.models.url import UrlAnalysisResult


class MessageAnalysisRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)


class MessageIndicator(BaseModel):
    category: str
    severity: str
    description: str
    evidence: str


class ScamSignal(BaseModel):
    type: str
    severity: Literal["low", "medium", "high"]
    evidence: str


class ScamAssessment(BaseModel):
    classification: Literal["low", "suspicious", "high"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    has_scam_intent: bool
    impersonates_entity: bool
    requests_money: bool
    requests_credentials: bool
    uses_urgency: bool
    has_suspicious_instructions: bool
    has_url: bool
    claims_transaction: bool
    signals: list[ScamSignal] = Field(default_factory=list)
    reasoning: str


class MessageURLAssessment(BaseModel):
    submitted_url: str
    url_analysis: UrlAnalysisResult
    phishing_analysis: PhishingAnalysisResult
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)


class AIExplanation(BaseModel):
    status: Literal["available", "unavailable", "malformed", "not_requested"]
    summary: str | None = None
    suspicious_indicators: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    scam_assessment: ScamAssessment | None = None
    advisory_note: str = "AI interpretation is advisory and is not verified threat intelligence."


class MessageAnalysisResponse(BaseModel):
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_email_addresses: list[str] = Field(default_factory=list)
    extracted_phone_numbers: list[str] = Field(default_factory=list)
    deterministic_indicators: list[MessageIndicator] = Field(default_factory=list)
    social_engineering_indicators: list[MessageIndicator] = Field(default_factory=list)
    urgency_indicators: list[MessageIndicator] = Field(default_factory=list)
    payment_request_indicators: list[MessageIndicator] = Field(default_factory=list)
    sensitive_information_indicators: list[MessageIndicator] = Field(default_factory=list)
    impersonation_indicators: list[MessageIndicator] = Field(default_factory=list)
    suspicious_contact_indicators: list[MessageIndicator] = Field(default_factory=list)
    url_threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)
    url_assessments: list[MessageURLAssessment] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    ai_explanation: AIExplanation
    limitations: list[str] = Field(default_factory=list)
