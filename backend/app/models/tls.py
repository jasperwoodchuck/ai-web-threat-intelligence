from pydantic import BaseModel, Field


class TlsFinding(BaseModel):
    type: str
    severity: str
    description: str
    evidence: str


class TlsCertificate(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    is_expired: bool | None = None
    san_names: list[str] = Field(default_factory=list)
    hostname_matches: bool | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    signature_algorithm: str | None = None


class TlsCertificateChainEntry(BaseModel):
    subject: str
    issuer: str
    serial_number: str


class CertificateTransparencyStatus(BaseModel):
    status: str = "not_checked"
    reason: str = "Certificate Transparency logs are not checked in this milestone."


class CertificateRevocationStatus(BaseModel):
    status: str = "not_checked"
    reason: str = "Certificate revocation and distrust sources are not checked in this milestone."


class TlsAnalysisResult(BaseModel):
    status: str
    supported: bool
    connection_successful: bool
    hostname: str | None = None
    port: int | None = None
    protocol_version: str | None = None
    certificate_verified: bool | None = None
    certificate: TlsCertificate | None = None
    certificate_chain: list[TlsCertificateChainEntry] = Field(default_factory=list)
    certificate_transparency: CertificateTransparencyStatus = Field(
        default_factory=CertificateTransparencyStatus
    )
    certificate_revocation: CertificateRevocationStatus = Field(
        default_factory=CertificateRevocationStatus
    )
    findings: list[TlsFinding] = Field(default_factory=list)
    trust_note: str = (
        "A valid TLS certificate supports transport identity and encryption; it does not prove website legitimacy."
    )
