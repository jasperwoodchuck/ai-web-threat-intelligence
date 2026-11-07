from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from app.analyzers import tls as tls_module
from app.analyzers.tls import TlsAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.dns import DnsAnalysisResult

_NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)


def build_certificate(
    *,
    key_size: int = 2048,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    san_name: str = "example.com",
) -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, san_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Issuing CA"),
        ]
    )
    before = not_before or _NOW - timedelta(days=2)
    after = not_after or _NOW + timedelta(days=90)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(0x123456)
        .not_valid_before(before.replace(tzinfo=None))
        .not_valid_after(after.replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def make_url(url: str = "https://example.com/path"):
    return UrlAnalyzer().analyze(url)


def make_dns(hostname: str = "example.com") -> DnsAnalysisResult:
    return DnsAnalysisResult(
        hostname=hostname,
        status="ok",
        resolution_succeeded=True,
        ipv4_addresses=["8.8.8.8"],
    )


class FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeTlsSocket:
    def __init__(self, certificate_der: bytes, protocol: str = "TLSv1.3"):
        self.certificate_der = certificate_der
        self.protocol = protocol

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def version(self) -> str:
        return self.protocol

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, Any]:
        return self.certificate_der if binary_form else {}

    def get_verified_chain(self) -> list[bytes]:
        return [self.certificate_der]


class FakeTlsContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self, certificate_der: bytes, protocol: str = "TLSv1.3"):
        self.session = FakeTlsSocket(certificate_der, protocol)

    def wrap_socket(self, raw_socket, *, server_hostname: str):
        assert isinstance(raw_socket, FakeRawSocket)
        assert server_hostname == "example.com"
        return self.session


def mock_tls(monkeypatch, certificate_der: bytes, protocol: str = "TLSv1.3") -> None:
    context = FakeTlsContext(certificate_der, protocol)
    monkeypatch.setattr(tls_module.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )


def test_valid_certificate_is_retrieved_and_hostname_matches(monkeypatch) -> None:
    mock_tls(monkeypatch, build_certificate())

    result = TlsAnalyzer(clock=lambda: _NOW).analyze(make_url(), make_dns())

    assert result.status == "ok"
    assert result.supported is True
    assert result.connection_successful is True
    assert result.certificate_verified is True
    assert result.certificate is not None
    assert result.certificate.hostname_matches is True
    assert result.certificate.is_expired is False
    assert result.certificate.san_names == ["example.com"]
    assert len(result.certificate_chain) == 1
    assert "example.com" in result.certificate_chain[0].subject


def test_expired_certificate_is_flagged() -> None:
    der = build_certificate(not_after=_NOW - timedelta(days=1))
    certificate, findings = TlsAnalyzer(clock=lambda: _NOW)._parse_certificate(der)

    assert certificate is not None
    assert certificate.is_expired is True
    assert any(item.type == "certificate_expired" for item in findings)


def test_expired_certificate_verification_failure_is_structured(monkeypatch) -> None:
    class ExpiredContext:
        def wrap_socket(self, _raw_socket, *, server_hostname: str):
            assert server_hostname == "example.com"
            raise ssl.SSLCertVerificationError(10, "certificate has expired")

    monkeypatch.setattr(tls_module.ssl, "create_default_context", ExpiredContext)
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda _address, timeout: FakeRawSocket(),
    )

    result = TlsAnalyzer().analyze(make_url(), make_dns())

    assert result.connection_successful is False
    assert result.certificate_verified is False
    assert result.findings[0].type == "certificate_expired"


def test_hostname_mismatch_is_structured_without_trusting_the_certificate(monkeypatch) -> None:
    class MismatchingContext:
        def wrap_socket(self, _raw_socket, *, server_hostname: str):
            assert server_hostname == "example.com"
            raise ssl.SSLCertVerificationError(62, "Hostname mismatch")

    monkeypatch.setattr(tls_module.ssl, "create_default_context", MismatchingContext)
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda _address, timeout: FakeRawSocket(),
    )

    result = TlsAnalyzer().analyze(make_url(), make_dns())

    assert result.connection_successful is False
    assert result.certificate_verified is False
    assert result.certificate is not None
    assert result.certificate.hostname_matches is False
    assert result.findings[0].type == "hostname_mismatch"


def test_weak_public_key_configuration_is_reported(monkeypatch) -> None:
    mock_tls(monkeypatch, build_certificate(key_size=1024))

    result = TlsAnalyzer(clock=lambda: _NOW).analyze(make_url(), make_dns())

    assert result.certificate is not None
    assert result.certificate.public_key_algorithm == "RSA"
    assert result.certificate.public_key_size == 1024
    assert any(item.type == "weak_public_key" for item in result.findings)


def test_certificate_issuer_is_extracted(monkeypatch) -> None:
    mock_tls(monkeypatch, build_certificate())

    result = TlsAnalyzer(clock=lambda: _NOW).analyze(make_url(), make_dns())

    assert result.certificate is not None
    assert "Example Issuing CA" in (result.certificate.issuer or "")


def test_certificate_signature_algorithm_is_extracted(monkeypatch) -> None:
    mock_tls(monkeypatch, build_certificate())

    result = TlsAnalyzer(clock=lambda: _NOW).analyze(make_url(), make_dns())

    assert result.certificate is not None
    assert "sha256" in (result.certificate.signature_algorithm or "").lower()


def test_negotiated_tls_protocol_is_extracted(monkeypatch) -> None:
    mock_tls(monkeypatch, build_certificate(), protocol="TLSv1.3")

    result = TlsAnalyzer(clock=lambda: _NOW).analyze(make_url(), make_dns())

    assert result.protocol_version == "TLSv1.3"


def test_tls_connection_failure_is_returned_as_a_finding(monkeypatch) -> None:
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ConnectionRefusedError("refused")),
    )

    result = TlsAnalyzer().analyze(make_url(), make_dns())

    assert result.status == "error"
    assert result.connection_successful is False
    assert result.findings[0].type == "connection_failed"


def test_http_url_does_not_attempt_tls(monkeypatch) -> None:
    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("HTTP must not attempt a TLS connection")

    monkeypatch.setattr(tls_module.socket, "create_connection", unexpected_connection)

    result = TlsAnalyzer().analyze(make_url("http://example.com/path"), make_dns())

    assert result.status == "not_applicable"
    assert result.supported is False
    assert result.findings == []


def test_private_or_internal_destinations_are_never_connected(monkeypatch) -> None:
    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("private destinations must be blocked")

    monkeypatch.setattr(tls_module.socket, "create_connection", unexpected_connection)
    private_dns = DnsAnalysisResult(
        hostname="example.com",
        status="ok",
        resolution_succeeded=True,
        ipv4_addresses=["127.0.0.1"],
    )

    result = TlsAnalyzer().analyze(make_url(), private_dns)

    assert result.status == "error"
    assert result.findings[0].type == "destination_not_public"


def test_certificate_transparency_is_explicitly_unchecked() -> None:
    result = TlsAnalyzer().analyze(make_url("http://example.com/"), make_dns())

    assert result.certificate_transparency.status == "not_checked"
    assert "not checked" in result.certificate_transparency.reason
