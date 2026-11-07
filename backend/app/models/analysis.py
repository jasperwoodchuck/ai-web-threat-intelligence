from pydantic import BaseModel

from app.models.dns import DnsAnalysisResult
from app.models.http import HttpAnalysisResult
from app.models.phishing import PhishingAnalysisResult, TyposquattingAnalysis
from app.models.risk import RiskAssessment
from app.models.tls import TlsAnalysisResult
from app.models.url import UrlAnalysisResult
from app.threat_intel.base import ThreatIntelResult


class UrlAnalysisResponse(BaseModel):
    url_analysis: UrlAnalysisResult
    dns_analysis: DnsAnalysisResult
    phishing_analysis: PhishingAnalysisResult
    typosquatting: TyposquattingAnalysis
    tls_analysis: TlsAnalysisResult
    http_analysis: HttpAnalysisResult
    threat_intelligence: ThreatIntelResult
    risk_assessment: RiskAssessment
