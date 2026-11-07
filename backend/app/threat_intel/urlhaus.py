"""URLhaus Community API adapter. This module only contacts URLhaus, never targets."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult, ThreatIntelStatus

_URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
_MAX_RESPONSE_BYTES = 64 * 1024


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str):
        return None


class UrlhausProvider(ThreatIntelProvider):
    """Query the official URLhaus URL lookup API with an optional Auth-Key."""

    def __init__(self, api_key: str | None = None, timeout: float = 4.0) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("URLHAUS_API_KEY")
        self.timeout = timeout

    def lookup(self, indicator: str) -> ThreatIntelResult:
        checked_at = datetime.now(UTC)
        is_url = indicator.lower().startswith(("http://", "https://"))
        if not is_url and (
            not indicator
            or any(char.isspace() or char in "/?#@:" for char in indicator)
        ):
            return self._unavailable(
                indicator, "A normalized HTTP(S) URL or hostname is required.", checked_at
            )
        if len(indicator) > 4096:
            return self._unavailable(indicator, "The submitted indicator is too long.", checked_at)
        if is_url:
            indicator = self._remove_unneeded_url_data(indicator)
            if indicator is None:
                return self._unavailable(
                    "", "A normalized HTTP(S) URL with a hostname is required.", checked_at
                )
        if not self.api_key:
            return self._unavailable(
                indicator, "URLHAUS_API_KEY is not configured.", checked_at
            )

        endpoint = _URLHAUS_ENDPOINT if is_url else _URLHAUS_HOST_ENDPOINT
        field = "url" if is_url else "host"
        request = Request(
            endpoint,
            data=urlencode({field: indicator}).encode("ascii"),
            headers={
                "Auth-Key": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "web-threat-intelligence-v2/0.1",
            },
            method="POST",
        )
        try:
            opener = build_opener(_NoRedirectHandler)
            with opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    return self._unavailable(
                        indicator, f"URLhaus returned HTTP {response.status}.", checked_at
                    )
                payload_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(payload_bytes) > _MAX_RESPONSE_BYTES:
                return self._unavailable(indicator, "URLhaus response exceeded the size limit.", checked_at)
            payload = json.loads(payload_bytes)
        except HTTPError as error:
            detail = "rate limited the request" if error.code == 429 else f"returned HTTP {error.code}"
            return self._unavailable(indicator, f"URLhaus {detail}.", checked_at)
        except (TimeoutError, URLError, OSError) as error:
            if isinstance(error, URLError) and isinstance(error.reason, TimeoutError):
                detail = "request timed out"
            elif isinstance(error, TimeoutError):
                detail = "request timed out"
            else:
                detail = "request failed"
            return self._unavailable(indicator, f"URLhaus {detail}.", checked_at)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._unavailable(indicator, "URLhaus returned invalid JSON.", checked_at)
        except Exception:
            return self._unavailable(
                indicator, "URLhaus request or response handling failed.", checked_at
            )

        if not isinstance(payload, dict):
            return self._unavailable(indicator, "URLhaus returned an unexpected response.", checked_at)
        query_status = payload.get("query_status")
        if query_status == "no_results":
            return ThreatIntelResult(
                status=ThreatIntelStatus.NO_MATCH,
                matched=False,
                source="URLhaus",
                indicator=indicator,
                evidence={"query_status": "no_results"},
                checked_at=checked_at,
            )
        entries = payload.get("urls")
        if query_status == "ok" and isinstance(payload.get("threat"), str):
            entries = [payload]
        if query_status != "ok" or not isinstance(entries, list) or not entries:
            return self._unavailable(indicator, "URLhaus response did not contain a valid lookup result.", checked_at)
        entry = entries[0]
        if not isinstance(entry, dict) or not isinstance(entry.get("threat"), str):
            return self._unavailable(indicator, "URLhaus result fields were malformed.", checked_at)

        reference = self._trusted_reference(entry.get("urlhaus_reference"))
        tags = entry.get("tags")
        safe_tags = [tag[:80] for tag in tags[:20] if isinstance(tag, str)] if isinstance(tags, list) else []
        evidence: dict[str, object] = {"query_status": "ok"}
        for key in ("url_status", "date_added"):
            value = entry.get(key)
            if isinstance(value, str):
                evidence[key] = value[:100]
        if safe_tags:
            evidence["tags"] = safe_tags
        return ThreatIntelResult(
            status=ThreatIntelStatus.MATCHED,
            matched=True,
            source="URLhaus",
            indicator=indicator,
            match_scope="url" if is_url else "host",
            threat_type=entry["threat"][:100],
            confidence=1.0,
            evidence=evidence,
            reference=reference,
            checked_at=checked_at,
        )

    @staticmethod
    def _remove_unneeded_url_data(url: str) -> str | None:
        """Strip URL userinfo and fragments before sharing an indicator with URLhaus."""
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
            port = parts.port
        except ValueError:
            return None
        if parts.scheme.lower() not in {"http", "https"} or hostname is None:
            return None
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname.lower() + (f":{port}" if port is not None else "")
        return f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}" + (
            f"?{parts.query}" if parts.query else ""
        )

    @staticmethod
    def _trusted_reference(value: object) -> str | None:
        if not isinstance(value, str) or len(value) > 500:
            return None
        if value.startswith("https://urlhaus.abuse.ch/"):
            return value
        return None

    @staticmethod
    def _unavailable(indicator: str, error: str, checked_at: datetime) -> ThreatIntelResult:
        return ThreatIntelResult(
            status=ThreatIntelStatus.UNAVAILABLE,
            matched=None,
            source="URLhaus",
            indicator=indicator,
            error=error,
            checked_at=checked_at,
        )
