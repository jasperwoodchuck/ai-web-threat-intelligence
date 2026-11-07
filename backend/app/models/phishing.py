from pydantic import BaseModel, Field


class PhishingIndicator(BaseModel):
    type: str
    severity: str
    description: str
    evidence: str
    score_contribution: int


class FraudUrlSignal(BaseModel):
    status: str
    result: dict[str, object] | None = None
    score_contribution: int = 0
    error: str | None = None


class TyposquattingAnalysis(BaseModel):
    detected: bool = False
    submitted_domain: str | None = None
    possible_intended_site: str | None = None
    similarity: float | None = Field(default=None, ge=0, le=1)
    edit_distance: int | None = Field(default=None, ge=0)


class PhishingAnalysisResult(BaseModel):
    is_suspicious: bool
    score: int = Field(ge=0, le=100)
    indicators: list[PhishingIndicator] = Field(default_factory=list)
    fraudurl: FraudUrlSignal
    typosquatting: TyposquattingAnalysis = Field(default_factory=TyposquattingAnalysis)
