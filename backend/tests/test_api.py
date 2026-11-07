from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.analyzers.dns import DnsAnalyzer
from app import main
from app.models.phishing import FraudUrlSignal, PhishingAnalysisResult
from app.models.tls import TlsAnalysisResult, TlsCertificate
from app.main import app

client = TestClient(app)


def test_fastapi_application_imports() -> None:
    assert isinstance(app, FastAPI)


def test_health_endpoint_works() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_https_url_analysis_works_through_api(monkeypatch) -> None:
    class FakeResolver:
        def resolve(self, hostname: str, record_type: str, lifetime: float):
            assert hostname == "example.com"
            assert lifetime > 0
            if record_type == "A":
                return [SimpleNamespace(address="192.0.2.20")]
            return []

    monkeypatch.setattr(main, "dns_analyzer", DnsAnalyzer(resolver=FakeResolver()))

    class FakePhishingAnalyzer:
        def analyze(self, url_analysis):
            assert url_analysis.hostname == "example.com"
            return PhishingAnalysisResult(
                is_suspicious=False,
                score=0,
                fraudurl=FraudUrlSignal(status="ok", result={"fraud_verdict": "LEGITIMATE"}),
            )

    monkeypatch.setattr(main, "phishing_analyzer", FakePhishingAnalyzer())

    class FakeTlsAnalyzer:
        def analyze(self, url_analysis, dns_analysis):
            assert url_analysis.hostname == "example.com"
            assert dns_analysis.hostname == "example.com"
            return TlsAnalysisResult(
                status="ok",
                supported=True,
                connection_successful=True,
                hostname="example.com",
                port=443,
                protocol_version="TLSv1.3",
                certificate_verified=True,
                certificate=TlsCertificate(hostname_matches=True),
            )

    monkeypatch.setattr(main, "tls_analyzer", FakeTlsAnalyzer())
    response = client.post(
        "/api/v1/analyze/url", json={"url": "https://example.com/login"}
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "url_analysis",
        "dns_analysis",
        "phishing_analysis",
        "risk_assessment",
        "tls_analysis",
    }
    assert body["url_analysis"]["is_valid"] is True
    assert body["url_analysis"]["normalized_url"] == "https://example.com/login"
    assert body["url_analysis"]["registered_domain"] == "example.com"
    assert body["dns_analysis"]["hostname"] == "example.com"
    assert body["dns_analysis"]["ipv4_addresses"] == ["192.0.2.20"]
    assert body["phishing_analysis"]["is_suspicious"] is False
    assert body["phishing_analysis"]["fraudurl"]["result"]["fraud_verdict"] == "LEGITIMATE"
    assert body["risk_assessment"]["classification"] == "Inconclusive"
    assert body["risk_assessment"]["score"] == 0
    assert body["tls_analysis"]["protocol_version"] == "TLSv1.3"


def test_invalid_url_returns_422() -> None:
    response = client.post(
        "/api/v1/analyze/url", json={"url": "https:///missing-host"}
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "URL must include a hostname."


def test_unsupported_scheme_returns_422() -> None:
    response = client.post(
        "/api/v1/analyze/url", json={"url": "ftp://example.com/file"}
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Only HTTP and HTTPS URLs are supported."
