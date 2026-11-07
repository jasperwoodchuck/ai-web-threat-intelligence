from pydantic import BaseModel


class UrlAnalysisRequest(BaseModel):
    url: str


class UrlAnalysisResult(BaseModel):
    original_url: str
    normalized_url: str | None = None
    scheme: str | None = None
    hostname: str | None = None
    port: int | None = None
    path: str | None = None
    has_query: bool = False
    has_fragment: bool = False
    has_username: bool = False
    has_password: bool = False
    registered_domain: str | None = None
    subdomain: str | None = None
    public_suffix: str | None = None
    is_ip_address: bool = False
    is_valid: bool
    validation_error: str | None = None
