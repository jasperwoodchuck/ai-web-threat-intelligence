from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.models.dns import DnsAnalysisResult
from app.models.http import HttpAnalysisResult, HttpFinding
from app.models.url import UrlAnalysisResult

DEFAULT_HTTP_TIMEOUT_SECONDS = 4.0
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
_MAX_HEADER_VALUE_CHARS = 2048
_SECURITY_HEADER_NAMES = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "location",
    "content-type",
    "server",
)
_FRAME_ANCESTORS = re.compile(r"(?:^|;)\s*frame-ancestors(?:\s|;|$)", re.IGNORECASE)


class _HeaderSizeLimitExceeded(http.client.HTTPException):
    pass


class _BoundedHeaderReader:
    """Enforce a total header block limit while http.client parses the response."""

    def __init__(self, source: object, limit: int) -> None:
        self._source = source
        self._limit = limit
        self.bytes_read = 0

    def readline(self, size: int = -1) -> bytes:
        remaining = self._limit - self.bytes_read
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        line = self._source.readline(requested)  # type: ignore[attr-defined]
        self.bytes_read += len(line)
        if self.bytes_read > self._limit:
            raise _HeaderSizeLimitExceeded("Response headers exceeded the size limit.")
        return line

    def __getattr__(self, name: str) -> object:
        return getattr(self._source, name)


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def begin(self) -> None:
        if self.headers is None:
            self.fp = _BoundedHeaderReader(self.fp, MAX_RESPONSE_HEADER_BYTES)
        super().begin()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    response_class = _BoundedHTTPResponse

    def __init__(self, hostname: str, port: int, address: str, timeout: float) -> None:
        super().__init__(hostname, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), timeout=self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = _BoundedHTTPResponse

    def __init__(
        self,
        hostname: str,
        port: int,
        address: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._address, self.port), timeout=self.timeout
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


ConnectionFactory = Callable[..., http.client.HTTPConnection]


class HttpAnalyzer:
    """Fetch response metadata with one bounded HEAD request and no redirect following."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._timeout = timeout
        self._connection_factory = connection_factory

    def analyze(
        self,
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult | None = None,
    ) -> HttpAnalysisResult:
        hostname = url_analysis.hostname
        scheme = url_analysis.scheme
        default_port = 443 if scheme == "https" else 80
        port = url_analysis.port if url_analysis.port is not None else default_port
        if not url_analysis.is_valid or scheme not in {"http", "https"} or not hostname:
            return self._failure(
                scheme,
                hostname,
                port,
                "HTTP analysis requires a valid HTTP or HTTPS URL.",
                "unsupported_url",
            )

        address, reason = self._public_address(url_analysis, dns_analysis)
        if reason or address is None:
            finding_type = (
                "destination_not_public"
                if reason
                and (
                    "not public" in reason
                    or "non-public" in reason
                    or "invalid address" in reason
                )
                else "dns_resolution_unavailable"
            )
            return self._failure(
                scheme,
                hostname,
                port,
                reason or "No verified public destination address is available.",
                finding_type,
            )

        connection: http.client.HTTPConnection | None = None
        try:
            request_target, safe_url = self._request_target(url_analysis)
            if self._connection_factory is None:
                connection = self._make_connection(scheme, hostname, port, address)
            else:
                connection = self._connection_factory(
                    scheme=scheme,
                    hostname=hostname,
                    port=port,
                    address=address,
                    timeout=self._timeout,
                )
            connection.request(
                "HEAD",
                request_target,
                headers={
                    "Host": self._host_header(hostname, url_analysis.port, scheme),
                    "User-Agent": "WebThreatIntelligenceScanner/0.1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            raw_headers = response.getheaders()
            header_size = getattr(
                getattr(response, "fp", None),
                "bytes_read",
                sum(len(key) + len(value) + 4 for key, value in raw_headers),
            )
            headers = self._security_headers(raw_headers)
            redirect_code = (
                response.status
                if 300 <= response.status < 400 and response.status != 304
                else None
            )
            raw_location = next(
                (value for name, value in raw_headers if name.lower() == "location"),
                None,
            )
            redirect_location = (
                self._sanitize_location(safe_url, raw_location)
                if raw_location is not None
                else None
            )
            headers["location"] = redirect_location
            findings = self._findings(
                scheme,
                response.status,
                headers,
                redirect_code,
                redirect_location,
                raw_location is not None,
                safe_url,
            )
            return HttpAnalysisResult(
                status="ok",
                supported=True,
                request_successful=True,
                scheme=scheme,
                hostname=hostname,
                port=port,
                status_code=response.status,
                security_headers=headers,
                headers_size_bytes=header_size,
                redirect_detected=redirect_code is not None,
                redirect_status_code=redirect_code,
                redirect_location=redirect_location,
                final_behavior=(
                    "redirect_not_followed"
                    if redirect_code is not None
                    else "response_received"
                ),
                findings=findings,
            )
        except _HeaderSizeLimitExceeded:
            return self._failure(
                scheme,
                hostname,
                port,
                "Response headers exceeded the 64 KiB limit.",
                "response_headers_too_large",
            )
        except (socket.timeout, TimeoutError):
            return self._failure(
                scheme,
                hostname,
                port,
                "HTTP response timed out.",
                "http_timeout",
            )
        except ssl.SSLCertVerificationError:
            return self._failure(
                scheme,
                hostname,
                port,
                "HTTPS response could not be inspected because certificate verification failed.",
                "http_tls_verification_failed",
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            return self._failure(
                scheme,
                hostname,
                port,
                "Could not retrieve HTTP response metadata.",
                "http_request_failed",
            )
        except Exception:
            return self._failure(
                scheme,
                hostname,
                port,
                "HTTP analysis failed unexpectedly.",
                "http_analysis_failed",
            )
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass

    def _make_connection(
        self, scheme: str, hostname: str, port: int, address: str
    ) -> http.client.HTTPConnection:
        if scheme == "https":
            return _PinnedHTTPSConnection(
                hostname,
                port,
                address,
                self._timeout,
                ssl.create_default_context(),
            )
        return _PinnedHTTPConnection(hostname, port, address, self._timeout)

    @staticmethod
    def _public_address(
        url_analysis: UrlAnalysisResult,
        dns_analysis: DnsAnalysisResult | None,
    ) -> tuple[str | None, str | None]:
        hostname = url_analysis.hostname
        if not hostname:
            return None, "URL hostname is missing."
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None:
            if not address.is_global:
                return None, "Request was blocked because the destination is not public."
            return address.compressed, None
        if dns_analysis is None or dns_analysis.hostname.lower() != hostname.lower():
            return None, "Matching DNS analysis for the submitted hostname is required."
        values = dns_analysis.ipv4_addresses + dns_analysis.ipv6_addresses
        if not values:
            return None, "Request was not made because DNS returned no addresses."
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for value in values:
            try:
                resolved = ipaddress.ip_address(value)
            except ValueError:
                return None, "Request was blocked because DNS returned an invalid address."
            if not resolved.is_global:
                return None, "Request was blocked because DNS included a non-public address."
            parsed_addresses.append(resolved)
        return parsed_addresses[0].compressed, None

    @staticmethod
    def _request_target(url_analysis: UrlAnalysisResult) -> tuple[str, str]:
        parts = urlsplit(url_analysis.normalized_url or "")
        target = parts.path or "/"
        if parts.query:
            target += f"?{parts.query}"
        authority = HttpAnalyzer._host_header(
            url_analysis.hostname or "", url_analysis.port, url_analysis.scheme
        )
        safe_url = urlunsplit((url_analysis.scheme or "", authority, parts.path or "/", "", ""))
        return target, safe_url

    @staticmethod
    def _host_header(hostname: str, port: int | None, scheme: str | None) -> str:
        host = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if scheme == "https" else 80
        return f"{host}:{port}" if port is not None and port != default_port else host

    @staticmethod
    def _security_headers(headers: list[tuple[str, str]]) -> dict[str, str | None]:
        values: dict[str, list[str]] = {name: [] for name in _SECURITY_HEADER_NAMES}
        for name, value in headers:
            normalized = name.lower()
            if normalized in values:
                cleaned = "".join(
                    character
                    for character in value
                    if (character >= " " and character != "\x7f") or character == "\t"
                ).strip()
                values[normalized].append(cleaned[:_MAX_HEADER_VALUE_CHARS])
        return {
            name: ", ".join(items) if items else None for name, items in values.items()
        }

    @classmethod
    def _sanitize_location(cls, request_url: str, location: str) -> str | None:
        try:
            parts = urlsplit(urljoin(request_url, location.strip()))
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                return None
            host = parts.hostname.lower()
            if ":" in host:
                host = f"[{host}]"
            port = parts.port
            if port is not None and port != (443 if parts.scheme.lower() == "https" else 80):
                host = f"{host}:{port}"
            # Query, fragment, and any user-info are deliberately not returned.
            return urlunsplit((parts.scheme.lower(), host, parts.path or "/", "", ""))[:2048]
        except ValueError:
            return None

    @classmethod
    def _findings(
        cls,
        scheme: str,
        status_code: int,
        headers: dict[str, str | None],
        redirect_code: int | None,
        redirect_location: str | None,
        has_location: bool,
        request_url: str,
    ) -> list[HttpFinding]:
        findings: list[HttpFinding] = []
        is_redirect_response = 300 <= status_code < 400
        if scheme == "http":
            findings.append(
                HttpFinding(
                    type="insecure_http",
                    severity="medium",
                    description="The submitted URL uses unencrypted HTTP transport.",
                    evidence="scheme=http",
                    score_contribution=10,
                )
            )
        elif not headers.get("strict-transport-security"):
            findings.append(
                HttpFinding(
                    type="missing_hsts",
                    severity="low",
                    description="The HTTPS response does not advertise HTTP Strict Transport Security.",
                    evidence="strict-transport-security header is absent",
                    score_contribution=2,
                )
            )

        if not is_redirect_response and not headers.get("content-security-policy"):
            findings.append(
                HttpFinding(
                    type="missing_content_security_policy",
                    severity="low",
                    description="The response does not advertise a Content Security Policy.",
                    evidence="content-security-policy header is absent",
                    score_contribution=2,
                )
            )
        if not is_redirect_response and (headers.get("x-content-type-options") or "").lower() != "nosniff":
            findings.append(
                HttpFinding(
                    type="missing_nosniff",
                    severity="low",
                    description="The response does not set X-Content-Type-Options to nosniff.",
                    evidence="x-content-type-options is absent or not nosniff",
                    score_contribution=1,
                )
            )
        csp = headers.get("content-security-policy") or ""
        if (
            not is_redirect_response
            and not headers.get("x-frame-options")
            and not _FRAME_ANCESTORS.search(csp)
        ):
            findings.append(
                HttpFinding(
                    type="missing_frame_protection",
                    severity="low",
                    description="The response has no X-Frame-Options or CSP frame-ancestors policy.",
                    evidence="No recognized framing protection header or directive was found.",
                    score_contribution=1,
                )
            )
        if not is_redirect_response and not headers.get("referrer-policy"):
            findings.append(
                HttpFinding(
                    type="missing_referrer_policy",
                    severity="low",
                    description="The response does not set a Referrer-Policy header.",
                    evidence="referrer-policy header is absent",
                    score_contribution=1,
                )
            )

        if redirect_code is not None:
            if redirect_location is None:
                findings.append(
                    HttpFinding(
                        type="redirect_without_location",
                        severity="low",
                        description="A redirect response did not provide a usable Location target.",
                        evidence=f"HTTP {redirect_code}; redirect was not followed",
                        score_contribution=3,
                    )
                )
            else:
                findings.append(
                    HttpFinding(
                        type="redirect_not_followed",
                        severity="info",
                        description="The server returned a redirect; the target was recorded but not requested.",
                        evidence=f"HTTP {redirect_code} to {redirect_location}",
                        score_contribution=0,
                    )
                )
                target = urlsplit(redirect_location)
                origin = urlsplit(request_url)
                if origin.scheme == "https" and target.scheme == "http":
                    findings.append(
                        HttpFinding(
                            type="https_downgrade_redirect",
                            severity="high",
                            description="The HTTPS response redirects to an unencrypted HTTP URL.",
                            evidence=f"HTTP {redirect_code}; HTTPS to HTTP downgrade",
                            score_contribution=12,
                        )
                    )
                elif (
                    target.scheme,
                    target.hostname,
                    target.port or (443 if target.scheme == "https" else 80),
                ) != (
                    origin.scheme,
                    origin.hostname,
                    origin.port or (443 if origin.scheme == "https" else 80),
                ):
                    findings.append(
                        HttpFinding(
                            type="cross_origin_redirect",
                            severity="low",
                            description="The response redirects to a different origin; the destination was not contacted.",
                            evidence=f"HTTP {redirect_code}; target origin {target.scheme}://{target.netloc}",
                            score_contribution=3,
                        )
                    )
        elif has_location:
            findings.append(
                HttpFinding(
                    type="location_without_redirect_status",
                    severity="low",
                    description="The response includes a Location header without a redirect status.",
                    evidence=f"HTTP {status_code}; Location header present",
                    score_contribution=2,
                )
            )
        if status_code in {405, 501}:
            findings.append(
                HttpFinding(
                    type="head_method_unavailable",
                    severity="info",
                    description="The server does not support the metadata-only HEAD method.",
                    evidence=f"HTTP {status_code}; no GET fallback was attempted",
                    score_contribution=0,
                )
            )
        return findings

    @staticmethod
    def _failure(
        scheme: str | None,
        hostname: str | None,
        port: int | None,
        message: str,
        finding_type: str,
    ) -> HttpAnalysisResult:
        return HttpAnalysisResult(
            status="error",
            supported=scheme in {"http", "https"},
            request_successful=False,
            scheme=scheme,
            hostname=hostname,
            port=port,
            final_behavior="request_failed",
            error=message,
            findings=[
                HttpFinding(
                    type=finding_type,
                    severity="info",
                    description="HTTP response metadata could not be collected.",
                    evidence=message,
                    score_contribution=0,
                )
            ],
        )
