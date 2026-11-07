from pydantic import BaseModel

from app.models.dns import DnsAnalysisResult
from app.models.url import UrlAnalysisResult


class UrlAnalysisResponse(BaseModel):
    url_analysis: UrlAnalysisResult
    dns_analysis: DnsAnalysisResult
