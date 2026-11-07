from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_fastapi_application_imports() -> None:
    assert isinstance(app, FastAPI)


def test_health_endpoint_works() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_https_url_analysis_works_through_api() -> None:
    response = client.post(
        "/api/v1/analyze/url", json={"url": "https://example.com/login"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["is_valid"] is True
    assert body["normalized_url"] == "https://example.com/login"
    assert body["registered_domain"] == "example.com"


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
