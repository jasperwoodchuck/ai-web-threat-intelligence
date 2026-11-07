from pydantic import BaseModel, Field


class DnsMailServer(BaseModel):
    preference: int
    exchange: str


class DnsLookupError(BaseModel):
    record_type: str
    error_type: str
    message: str


class DnsAnalysisResult(BaseModel):
    hostname: str
    status: str
    resolution_succeeded: bool
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    cname_target: str | None = None
    mail_servers: list[DnsMailServer] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    errors: list[DnsLookupError] = Field(default_factory=list)
    reason: str | None = None
