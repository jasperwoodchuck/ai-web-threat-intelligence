from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
    x25519,
    x448,
)

from app.models.dns import DnsAnalysisResult
from app.models.tls import (
    CertificateRevocationStatus,
    TlsAnalysisResult,
    TlsCertificate,
    TlsCertificateChainEntry,
    TlsFinding,
)
from app.models.url import UrlAnalysisResult

DEFAULT_TLS_TIMEOUT_SECONDS = 4.0
_EXPIRING_SOON = timedelta(days=30)
_WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"}


class TlsAnalyzer:
    """Perform a verified TLS handshake to the URL's already resolved public address."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TLS_TIMEOUT_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._timeout = timeout
        self._clock = clock or (lambda: datetime.now(UTC))

    def analyze(
        self,
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult | None = None,
    ) -> TlsAnalysisResult:
        hostname = url_analysis.hostname
        default_port = (
            443
            if url_analysis.scheme == "https"
            else 80
            if url_analysis.scheme == "http"
            else None
        )
        port = url_analysis.port if url_analysis.port is not None else default_port
        if url_analysis.scheme == "http":
            return TlsAnalysisResult(
                status="not_applicable",
                supported=False,
                connection_successful=False,
                hostname=hostname,
                port=port,
            )
        if not url_analysis.is_valid or url_analysis.scheme != "https" or not hostname:
            return self._failed(
                hostname,
                port,
                "unsupported_url",
                "TLS analysis requires a valid HTTPS URL.",
                url_analysis.validation_error or "URL is not valid HTTPS.",
                supported=False,
            )

        address, unsafe_reason = self._public_address(url_analysis, dns_analysis)
        if unsafe_reason:
            return self._failed(
                hostname,
                port,
                "destination_not_public",
                "TLS connection was not attempted because the destination is not a verified public address.",
                unsafe_reason,
            )
        if address is None:
            return self._failed(
                hostname,
                port,
                "dns_resolution_unavailable",
                "TLS connection was not attempted because no resolved address is available.",
                "TLS connects only to public addresses supplied by DNS analysis.",
            )

        try:
            context = ssl.create_default_context()
            # Default context keeps CA chain verification and hostname verification enabled.
            with socket.create_connection((address, port), timeout=self._timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                    protocol = tls_socket.version()
                    der_certificate = tls_socket.getpeercert(binary_form=True)
                    if not der_certificate:
                        return self._failed(
                            hostname,
                            port,
                            "certificate_unavailable",
                            "TLS connected but did not provide certificate data.",
                            "The peer returned no certificate bytes.",
                            protocol_version=protocol,
                            connection_successful=True,
                            certificate_verified=True,
                        )
                    certificate, certificate_findings = self._parse_certificate(der_certificate)
                    chain, chain_findings = self._parse_chain(tls_socket)
                    findings = certificate_findings + chain_findings
                    if protocol in _WEAK_TLS_VERSIONS:
                        findings.append(
                            TlsFinding(
                                type="obsolete_tls_version",
                                severity="high",
                                description="The connection negotiated an obsolete TLS protocol version.",
                                evidence=protocol,
                            )
                        )
                    return TlsAnalysisResult(
                        status="ok",
                        supported=True,
                        connection_successful=True,
                        hostname=hostname,
                        port=port,
                        protocol_version=protocol,
                        certificate_verified=True,
                        certificate=certificate,
                        certificate_chain=chain,
                        findings=findings,
                    )
        except ssl.SSLCertVerificationError as exc:
            return self._verification_failure(hostname, port, exc)
        except (socket.timeout, TimeoutError) as exc:
            return self._failed(
                hostname,
                port,
                "connection_timeout",
                "TLS connection timed out.",
                str(exc) or type(exc).__name__,
            )
        except ssl.SSLError as exc:
            return self._failed(
                hostname,
                port,
                "tls_handshake_failed",
                "TLS handshake failed.",
                str(exc) or type(exc).__name__,
            )
        except OSError as exc:
            return self._failed(
                hostname,
                port,
                "connection_failed",
                "Could not establish the TLS connection.",
                str(exc) or type(exc).__name__,
            )
        except Exception as exc:
            return self._failed(
                hostname,
                port,
                "tls_analysis_failed",
                "TLS analysis could not complete.",
                f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _public_address(
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult | None,
    ) -> tuple[str | None, str | None]:
        hostname = url_analysis.hostname
        if not hostname:
            return None, "URL hostname is missing."
        if url_analysis.is_ip_address:
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                return None, "URL hostname was marked as an IP but could not be parsed."
            if not address.is_global:
                return None, f"Resolved address {address.compressed} is not public."
            return address.compressed, None
        if dns_analysis is None or dns_analysis.hostname.lower() != hostname.lower():
            return None, "Matching DNS analysis for this URL hostname is required."

        addresses = dns_analysis.ipv4_addresses + dns_analysis.ipv6_addresses
        if not addresses:
            return None, "DNS analysis returned no A or AAAA addresses."
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return None, f"DNS returned an invalid IP address: {value!r}."
            if not address.is_global:
                return None, f"Resolved address {address.compressed} is not public."
            parsed_addresses.append(address)
        return parsed_addresses[0].compressed, None

    def _parse_certificate(
        self,
        der_certificate: bytes,
    ) -> tuple[TlsCertificate | None, list[TlsFinding]]:
        try:
            cert = x509.load_der_x509_certificate(der_certificate)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            now = self._clock()
            san_names: list[str] = []
            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                san_names = [str(name.value) for name in san]
            except x509.ExtensionNotFound:
                pass

            public_key = cert.public_key()
            algorithm = self._public_key_algorithm(public_key)
            public_key_size = getattr(public_key, "key_size", None)
            signature_algorithm = self._signature_algorithm(cert)
            certificate = TlsCertificate(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial_number=hex(cert.serial_number),
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                is_expired=now > not_after,
                san_names=san_names,
                hostname_matches=True,  # The default SSL context verified host identity.
                public_key_algorithm=algorithm,
                public_key_size=public_key_size,
                signature_algorithm=signature_algorithm,
            )
        except Exception as exc:
            return None, [
                TlsFinding(
                    type="certificate_data_unavailable",
                    severity="medium",
                    description="Certificate bytes could not be parsed for metadata.",
                    evidence=f"{type(exc).__name__}: {exc}",
                )
            ]

        findings: list[TlsFinding] = []
        if now < not_before:
            findings.append(
                TlsFinding(
                    type="certificate_not_yet_valid",
                    severity="high",
                    description="The certificate validity period has not started.",
                    evidence=f"not_before={not_before.isoformat()}; current_time={now.isoformat()}",
                )
            )
        if now > not_after:
            findings.append(
                TlsFinding(
                    type="certificate_expired",
                    severity="high",
                    description="The certificate has expired.",
                    evidence=f"not_after={not_after.isoformat()}; current_time={now.isoformat()}",
                )
            )
        elif not_after - now <= _EXPIRING_SOON:
            findings.append(
                TlsFinding(
                    type="certificate_expires_soon",
                    severity="low",
                    description="The certificate expires within 30 days.",
                    evidence=f"not_after={not_after.isoformat()}",
                )
            )
        if algorithm == "RSA" and public_key_size is not None and public_key_size < 2048:
            findings.append(
                TlsFinding(
                    type="weak_public_key",
                    severity="high",
                    description="RSA public key is smaller than 2048 bits.",
                    evidence=f"algorithm=RSA; key_size={public_key_size}",
                )
            )
        elif algorithm == "EC" and public_key_size is not None and public_key_size < 224:
            findings.append(
                TlsFinding(
                    type="weak_public_key",
                    severity="high",
                    description="Elliptic-curve public key is smaller than 224 bits.",
                    evidence=f"algorithm=EC; key_size={public_key_size}",
                )
            )
        elif algorithm == "DSA" and public_key_size is not None and public_key_size < 2048:
            findings.append(
                TlsFinding(
                    type="weak_public_key",
                    severity="high",
                    description="DSA public key is smaller than 2048 bits.",
                    evidence=f"algorithm=DSA; key_size={public_key_size}",
                )
            )
        if signature_algorithm and any(
            weak_name in signature_algorithm.lower() for weak_name in ("md5", "sha1")
        ):
            findings.append(
                TlsFinding(
                    type="weak_signature_algorithm",
                    severity="high",
                    description="Certificate uses a legacy MD5 or SHA-1 signature hash.",
                    evidence=signature_algorithm,
                )
            )
        return certificate, findings

    @staticmethod
    def _public_key_algorithm(public_key: object) -> str:
        for key_type, name in (
            (rsa.RSAPublicKey, "RSA"),
            (ec.EllipticCurvePublicKey, "EC"),
            (dsa.DSAPublicKey, "DSA"),
            (ed25519.Ed25519PublicKey, "Ed25519"),
            (ed448.Ed448PublicKey, "Ed448"),
            (x25519.X25519PublicKey, "X25519"),
            (x448.X448PublicKey, "X448"),
        ):
            if isinstance(public_key, key_type):
                return name
        return type(public_key).__name__

    @staticmethod
    def _signature_algorithm(cert: x509.Certificate) -> str | None:
        oid = cert.signature_algorithm_oid
        name = getattr(oid, "_name", None) or oid.dotted_string
        try:
            digest = cert.signature_hash_algorithm
        except Exception:
            digest = None
        return f"{name} ({digest.name})" if digest is not None else name

    @staticmethod
    def _parse_chain(
        tls_socket: ssl.SSLSocket,
    ) -> tuple[list[TlsCertificateChainEntry], list[TlsFinding]]:
        get_chain = getattr(tls_socket, "get_verified_chain", None)
        if not callable(get_chain):
            return [], [
                TlsFinding(
                    type="certificate_chain_unavailable",
                    severity="info",
                    description="The TLS runtime does not expose the verified certificate chain.",
                    evidence="get_verified_chain() is unavailable.",
                )
            ]
        try:
            ders = get_chain()
            if not ders:
                return [], [
                    TlsFinding(
                        type="certificate_chain_unavailable",
                        severity="info",
                        description="The TLS runtime returned no verified chain entries.",
                        evidence="The peer certificate chain was empty.",
                    )
                ]
            chain = []
            for der in ders:
                cert = x509.load_der_x509_certificate(der)
                chain.append(
                    TlsCertificateChainEntry(
                        subject=cert.subject.rfc4514_string(),
                        issuer=cert.issuer.rfc4514_string(),
                        serial_number=hex(cert.serial_number),
                    )
                )
            return chain, []
        except Exception as exc:
            return [], [
                TlsFinding(
                    type="certificate_chain_unavailable",
                    severity="info",
                    description="The verified certificate chain could not be parsed.",
                    evidence=f"{type(exc).__name__}: {exc}",
                )
            ]

    @staticmethod
    def _verification_failure(
        hostname: str,
        port: int,
        error: ssl.SSLCertVerificationError,
    ) -> TlsAnalysisResult:
        message = getattr(error, "verify_message", None) or str(error)
        lowered = message.lower()
        if "hostname" in lowered or "ip address mismatch" in lowered:
            finding_type = "hostname_mismatch"
            description = "Certificate identity does not match the requested hostname."
            certificate = TlsCertificate(hostname_matches=False)
        elif "expired" in lowered:
            finding_type = "certificate_expired"
            description = "TLS certificate validation failed because the certificate has expired."
            certificate = None
        elif "not yet valid" in lowered:
            finding_type = "certificate_not_yet_valid"
            description = "TLS certificate validation failed because the certificate is not yet valid."
            certificate = None
        else:
            finding_type = "certificate_verification_failed"
            description = "TLS certificate chain or trust validation failed."
            certificate = None
        return TlsAnalysisResult(
            status="error",
            supported=True,
            connection_successful=False,
            hostname=hostname,
            port=port,
            certificate_verified=False,
            certificate=certificate,
            certificate_revocation=CertificateRevocationStatus(),
            findings=[
                TlsFinding(
                    type=finding_type,
                    severity="high",
                    description=description,
                    evidence=message,
                )
            ],
        )

    @staticmethod
    def _failed(
        hostname: str | None,
        port: int | None,
        finding_type: str,
        description: str,
        evidence: str,
        *,
        supported: bool = True,
        protocol_version: str | None = None,
        connection_successful: bool = False,
        certificate_verified: bool | None = None,
    ) -> TlsAnalysisResult:
        return TlsAnalysisResult(
            status="error",
            supported=supported,
            connection_successful=connection_successful,
            hostname=hostname,
            port=port,
            protocol_version=protocol_version,
            certificate_verified=certificate_verified,
            findings=[
                TlsFinding(
                    type=finding_type,
                    severity=(
                        "high"
                        if finding_type
                        in {"tls_handshake_failed", "certificate_unavailable"}
                        else "medium"
                    ),
                    description=description,
                    evidence=evidence,
                )
            ],
        )
