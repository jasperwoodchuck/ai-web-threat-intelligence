from pydantic import BaseModel, Field


class HttpFinding(BaseModel):
    type: str
    severity: str
    description: str
    evidence: str
    score_contribution: int = Field(ge=0, le=100)


class HttpAnalysisResult(BaseModel):
    status: str
    supported: bool
    request_successful: bool
    scheme: str | None = None
    hostname: str | None = None
    port: int | None = None
    request_method: str = "HEAD"
    status_code: int | None = None
    security_headers: dict[str, str | None] = Field(default_factory=dict)
    headers_size_bytes: int | None = None
    redirect_detected: bool = False
    redirect_status_code: int | None = None
    redirect_location: str | None = None
    final_behavior: str = "not_requested"
    error: str | None = None
    findings: list[HttpFinding] = Field(default_factory=list)
    trust_note: str = (
        "HTTP response metadata is limited evidence and does not establish whether a website is trustworthy."
    )
