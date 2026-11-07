from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit

import tldextract

from app.models.url import UrlAnalysisResult

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


class UrlAnalyzer:
    """Parse and normalize an HTTP(S) URL without making network requests."""

    def __init__(self, extractor: Callable[[str], object] | None = None) -> None:
        # The bundled Public Suffix List snapshot avoids cache writes and downloads.
        self._extractor = extractor or tldextract.TLDExtract(
            cache_dir=None, suffix_list_urls=()
        )

    def analyze(self, url: str) -> UrlAnalysisResult:
        parts: SplitResult | None = None
        try:
            if not isinstance(url, str) or not url:
                return self._invalid(
                    url if isinstance(url, str) else str(url),
                    "URL must not be empty.",
                )
            if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
                return self._invalid(
                    url, "URL contains whitespace or control characters."
                )
            if _INVALID_PERCENT_ESCAPE.search(url):
                return self._invalid(url, "URL contains an invalid percent escape.")

            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            hostname = parts.hostname
            port = parts.port  # Raises ValueError for malformed or out-of-range ports.
            has_username = parts.username is not None
            has_password = parts.password is not None
            has_query = "?" in url.split("#", maxsplit=1)[0]
            has_fragment = "#" in url

            if scheme not in {"http", "https"}:
                return self._invalid(
                    url,
                    "Only HTTP and HTTPS URLs are supported.",
                    parts=parts,
                    port=port,
                    has_username=has_username,
                    has_password=has_password,
                    has_query=has_query,
                    has_fragment=has_fragment,
                )
            if not parts.netloc or not hostname:
                return self._invalid(
                    url,
                    "URL must include a hostname.",
                    parts=parts,
                    port=port,
                    has_username=has_username,
                    has_password=has_password,
                    has_query=has_query,
                    has_fragment=has_fragment,
                )

            raw_authority = parts.netloc.rsplit("@", maxsplit=1)[-1]
            if raw_authority.endswith(":"):
                return self._invalid(
                    url,
                    "URL port must contain a number.",
                    parts=parts,
                    has_username=has_username,
                    has_password=has_password,
                    has_query=has_query,
                    has_fragment=has_fragment,
                )

            ip_address = self._parse_ip(hostname)
            if ip_address is not None:
                normalized_hostname = ip_address.compressed.lower()
                host_for_url = (
                    f"[{normalized_hostname}]"
                    if isinstance(ip_address, ipaddress.IPv6Address)
                    else normalized_hostname
                )
                registered_domain = subdomain = public_suffix = None
            else:
                normalized_hostname = self._normalize_dns_hostname(hostname)
                host_for_url = normalized_hostname
                registered_domain, subdomain, public_suffix = self._domain_parts(
                    normalized_hostname
                )

            userinfo = ""
            if "@" in parts.netloc:
                userinfo = f"{parts.netloc.rsplit('@', maxsplit=1)[0]}@"
            normalized_authority = f"{userinfo}{host_for_url}"
            if port is not None:
                normalized_authority += f":{port}"

            normalized_path = parts.path or "/"
            normalized_url = urlunsplit(
                (
                    scheme,
                    normalized_authority,
                    normalized_path,
                    parts.query,
                    parts.fragment,
                )
            )
            return UrlAnalysisResult(
                original_url=url,
                normalized_url=normalized_url,
                scheme=scheme,
                hostname=normalized_hostname,
                port=port,
                path=normalized_path,
                has_query=has_query,
                has_fragment=has_fragment,
                has_username=has_username,
                has_password=has_password,
                registered_domain=registered_domain,
                subdomain=subdomain,
                public_suffix=public_suffix,
                is_ip_address=ip_address is not None,
                is_valid=True,
            )
        except (UnicodeError, ValueError) as exc:
            return self._invalid(url, str(exc) or "URL is malformed.", parts=parts)

    @staticmethod
    def _parse_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(hostname)
        except ValueError:
            return None

    @staticmethod
    def _normalize_dns_hostname(hostname: str) -> str:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(
                "Hostname is not a valid internationalized domain name."
            ) from exc

        labels = ascii_hostname.removesuffix(".").split(".")
        if (
            not ascii_hostname
            or len(ascii_hostname) > 254
            or any(not _DNS_LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("Hostname is not syntactically valid.")
        return ascii_hostname

    def _domain_parts(self, hostname: str) -> tuple[str | None, str | None, str | None]:
        try:
            extracted = self._extractor(hostname)
        except Exception:
            return None, None, None
        return (
            getattr(extracted, "top_domain_under_public_suffix", None) or None,
            getattr(extracted, "subdomain", None) or None,
            getattr(extracted, "suffix", None) or None,
        )

    @staticmethod
    def _invalid(
        url: str,
        message: str,
        *,
        parts: SplitResult | None = None,
        port: int | None = None,
        has_username: bool = False,
        has_password: bool = False,
        has_query: bool | None = None,
        has_fragment: bool | None = None,
    ) -> UrlAnalysisResult:
        scheme = hostname = path = None
        if parts is not None:
            try:
                scheme = parts.scheme.lower() or None
                hostname = parts.hostname
                path = parts.path
            except ValueError:
                pass
        return UrlAnalysisResult(
            original_url=url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            has_query=(bool(parts.query) if parts else False)
            if has_query is None
            else has_query,
            has_fragment=(bool(parts.fragment) if parts else False)
            if has_fragment is None
            else has_fragment,
            has_username=has_username,
            has_password=has_password,
            is_ip_address=(UrlAnalyzer._parse_ip(hostname) is not None if hostname else False),
            is_valid=False,
            validation_error=message,
        )
