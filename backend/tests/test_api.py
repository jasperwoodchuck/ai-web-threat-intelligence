from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import main
from app.analyzers.dns import DnsAnalyzer
from app.analyzers.phishing import PhishingAnalyzer
from app.analyzers.reachability import ReachabilityResult
from app.models.dns import DnsAnalysisResult
from app.models.http import HttpAnalysisResult
from app.models.message import AIExplanation
from app.models.phishing import FraudUrlSignal, PhishingAnalysisResult, TyposquattingAnalysis
from app.models.tls import TlsAnalysisResult, TlsCertificate
from app.threat_intel.base import ThreatIntelResult, ThreatIntelStatus
from app.main import app

client = TestClient(app)


def test_fastapi_application_imports() -> None:
    assert isinstance(app, FastAPI)


def test_health_endpoint_works() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_allows_local_vite_origin_without_credentials() -> None:
    response = TestClient(main.app).options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


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

    class FakeHttpAnalyzer:
        def analyze(self, url_analysis, dns_analysis):
            assert url_analysis.hostname == "example.com"
            assert dns_analysis.hostname == "example.com"
            return HttpAnalysisResult(
                status="ok",
                supported=True,
                request_successful=True,
                scheme="https",
                hostname="example.com",
                port=443,
                status_code=200,
                final_behavior="response_received",
            )

    monkeypatch.setattr(main, "http_analyzer", FakeHttpAnalyzer())
    monkeypatch.setattr(main, "reachability_checker", SimpleNamespace(check=lambda *_: ReachabilityResult("reachable", "Website is reachable.", "Mock server responded.", 200)))
    monkeypatch.setattr(
        main,
        "ai_provider",
        SimpleNamespace(
            explain=lambda *_args: AIExplanation(
                status="available", summary="The checks show no listed threat match."
            )
        ),
    )
    monkeypatch.setattr(
        main,
        "threat_intel_provider",
        SimpleNamespace(
            lookup=lambda indicator: ThreatIntelResult(
                status=ThreatIntelStatus.NO_MATCH,
                matched=False,
                source="URLhaus",
                indicator=indicator,
            )
        ),
    )
    response = client.post(
        "/api/v1/analyze/url", json={"url": "https://example.com/login"}
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "availability",
        "url_analysis",
        "dns_analysis",
        "phishing_analysis",
        "typosquatting",
        "risk_assessment",
        "tls_analysis",
        "http_analysis",
        "threat_intelligence",
        "ai_explanation",
    }
    assert body["availability"]["status"] == "reachable"
    assert body["url_analysis"]["is_valid"] is True
    assert body["url_analysis"]["normalized_url"] == "https://example.com/login"
    assert body["url_analysis"]["registered_domain"] == "example.com"
    assert body["dns_analysis"]["hostname"] == "example.com"
    assert body["dns_analysis"]["ipv4_addresses"] == ["192.0.2.20"]
    assert body["phishing_analysis"]["is_suspicious"] is False
    assert body["phishing_analysis"]["fraudurl"]["result"]["fraud_verdict"] == "LEGITIMATE"
    assert body["typosquatting"]["detected"] is False
    assert body["risk_assessment"]["classification"] == "Inconclusive"
    assert body["risk_assessment"]["score"] == 0
    assert body["tls_analysis"]["protocol_version"] == "TLSv1.3"
    assert body["http_analysis"]["status_code"] == 200
    assert body["threat_intelligence"]["status"] == "no_match"
    assert body["threat_intelligence"]["matched"] is False
    assert body["ai_explanation"]["status"] == "available"


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


def test_yovtube_reaches_phishing_and_risk_analysis_through_api(monkeypatch) -> None:
    class FakeFraudUrl:
        def analyze(self, url: str) -> FraudUrlSignal:
            assert url == "https://yovtube.com/"
            return FraudUrlSignal(status="error", error="mocked unavailable")

    class FakeDnsAnalyzer:
        def analyze(self, hostname: str):
            return DnsAnalysisResult(
                hostname=hostname,
                status="ok",
                resolution_succeeded=True,
            )

    class FakeTlsAnalyzer:
        def analyze(self, url_analysis, dns_analysis):
            return TlsAnalysisResult(
                status="not_applicable",
                supported=False,
                connection_successful=False,
                hostname=url_analysis.hostname,
                port=443,
            )

    class FakeHttpAnalyzer:
        def analyze(self, url_analysis, dns_analysis):
            return HttpAnalysisResult(
                status="error",
                supported=True,
                request_successful=False,
                scheme="https",
                hostname=url_analysis.hostname,
                port=443,
                error="mocked unavailable",
            )

    monkeypatch.setattr(main, "dns_analyzer", FakeDnsAnalyzer())
    monkeypatch.setattr(
        main, "phishing_analyzer", PhishingAnalyzer(fraudurl_analyzer=FakeFraudUrl())
    )
    monkeypatch.setattr(main, "tls_analyzer", FakeTlsAnalyzer())
    monkeypatch.setattr(main, "http_analyzer", FakeHttpAnalyzer())
    monkeypatch.setattr(main, "reachability_checker", SimpleNamespace(check=lambda *_: ReachabilityResult("reachable", "Website is reachable.", "Mock server responded.", 200)))
    monkeypatch.setattr(
        main,
        "threat_intel_provider",
        SimpleNamespace(
            lookup=lambda indicator: ThreatIntelResult(
                status=ThreatIntelStatus.UNAVAILABLE,
                matched=None,
                source="URLhaus",
                indicator=indicator,
                error="mocked unavailable",
            )
        ),
    )

    response = client.post("/api/v1/analyze/url", json={"url": "https://yovtube.com"})

    assert response.status_code == 200
    body = response.json()
    indicator = next(
        item
        for item in body["phishing_analysis"]["indicators"]
        if item["type"] == "typosquatting_domain"
    )
    risk_signal = next(
        item
        for item in body["risk_assessment"]["contributing_indicators"]
        if item["indicator"] == "typosquatting_domain"
    )
    assert "youtube.com" in indicator["description"]
    assert "possible_intended_site=youtube.com" in indicator["evidence"]
    assert body["typosquatting"] == {
        "type": "typosquatting",
        "detected": True,
        "submitted_domain": "yovtube.com",
        "possible_intended_site": "youtube.com",
        "similarity": 0.86,
        "edit_distance": 1,
        "domain": "yovtube.com",
        "reference_domain": "youtube.com",
        "technique": "character_substitution",
        "severity": "medium",
        "evidence": "'v' replaces 'u' in the domain label.",
        "is_idn": False,
    }
    assert risk_signal["weight"] == 30
    assert risk_signal["description"] == (
        "yovtube.com may impersonate youtube.com using character substitution."
    )
    assert body["risk_assessment"]["score"] == 30


def test_nonexistent_typosquatting_url_returns_only_availability_and_detection(monkeypatch) -> None:
    detection = TyposquattingAnalysis(
        detected=True,
        submitted_domain="yovtube.com",
        possible_intended_site="youtube.com",
        similarity=0.86,
        edit_distance=1,
        domain="yovtube.com",
        reference_domain="youtube.com",
        technique="character_substitution",
        severity="medium",
        evidence="'v' replaces 'u' in the domain label.",
    )
    monkeypatch.setattr(
        main,
        "phishing_analyzer",
        SimpleNamespace(
            analyze=lambda _url: PhishingAnalysisResult(
                is_suspicious=True,
                score=30,
                fraudurl=FraudUrlSignal(status="skipped"),
                typosquatting=detection,
            )
        ),
    )
    monkeypatch.setattr(
        main,
        "reachability_checker",
        SimpleNamespace(
            check=lambda *_: ReachabilityResult(
                "not_found", "Website could not be found.", "DNS did not resolve."
            )
        ),
    )

    response = client.post("/api/v1/analyze/url", json={"url": "https://yovtube.com"})

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"availability", "typosquatting"}
    assert body["availability"]["status"] == "not_found"
    assert body["typosquatting"]["detected"] is True
    assert body["typosquatting"]["reference_domain"] == "youtube.com"
