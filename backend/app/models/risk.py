from enum import StrEnum

from pydantic import BaseModel, Field


class RiskClassification(StrEnum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"


class RiskEvidence(BaseModel):
    source: str
    indicator: str
    severity: str
    weight: int = Field(ge=0, le=100)
    description: str
    evidence: str


class RiskAssessment(BaseModel):
    classification: RiskClassification
    score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    contributing_indicators: list[RiskEvidence] = Field(default_factory=list)
    recommended_precautions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
