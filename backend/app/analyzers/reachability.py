from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class ReachabilityResult:
    status: str
    message: str
    details: str
    http_status: int | None = None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrlReachabilityChecker:
    """Bounded DNS and one-hop HTTP probe; availability is not a risk verdict."""

    def __init__(self, *, dns_timeout: float = 3.0, http_timeout: float = 4.0) -> None:
        self.dns_timeout = dns_timeout
        self.http_timeout = http_timeout

    def check(self, url: str, hostname: str) -> ReachabilityResult:
        try:
            socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            if exc.errno == socket.EAI_NONAME:
                return ReachabilityResult("not_found", "The website could not be found.", "The domain does not resolve in DNS.")
            return ReachabilityResult("error", "Website availability could not be determined.", "DNS lookup failed temporarily.")
        except (TimeoutError, OSError):
            return ReachabilityResult("error", "Website availability could not be determined.", "DNS lookup timed out or failed temporarily.")

        request = Request(url, method="HEAD", headers={"User-Agent": "WebThreatIntelligence/1.0"})
        opener = build_opener(_NoRedirect)
        try:
            response = opener.open(request, timeout=self.http_timeout)
            status = response.status
            response.close()
            return ReachabilityResult("reachable", "Website is reachable.", "The server responded to an HTTP request.", status)
        except HTTPError as exc:
            # Any HTTP response, including redirects and errors, proves a server responded.
            return ReachabilityResult("reachable", "Website is reachable.", "The server responded to an HTTP request.", exc.code)
        except (URLError, TimeoutError, OSError):
            if url.lower().startswith("https://"):
                fallback = "http://" + url[len("https://"):]
                try:
                    response = opener.open(Request(fallback, method="HEAD", headers={"User-Agent": "WebThreatIntelligence/1.0"}), timeout=self.http_timeout)
                    status = response.status
                    response.close()
                    return ReachabilityResult("reachable", "Website is reachable.", "The HTTPS probe failed, but HTTP responded.", status)
                except HTTPError as exc:
                    return ReachabilityResult("reachable", "Website is reachable.", "The HTTPS probe failed, but HTTP responded.", exc.code)
                except (URLError, TimeoutError, OSError):
                    pass
            return ReachabilityResult("unreachable", "The website exists but could not be reached.", "The domain resolves, but the server did not respond to the connection attempt.")
