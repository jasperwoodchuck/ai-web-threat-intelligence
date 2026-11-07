from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver

from app.models.dns import DnsAnalysisResult, DnsLookupError, DnsMailServer

DEFAULT_DNS_TIMEOUT_SECONDS = 1.5
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class DnsAnalyzer:
    """Resolve standard DNS records for a hostname using bounded lookups."""

    def __init__(
        self,
        *,
        resolver: object | None = None,
        timeout: float = DEFAULT_DNS_TIMEOUT_SECONDS,
    ) -> None:
        self._resolver = resolver if resolver is not None else dns.resolver.Resolver()
        self._timeout = timeout

    def analyze(self, hostname: str) -> DnsAnalysisResult:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            return DnsAnalysisResult(
                hostname=hostname,
                status="not_applicable",
                resolution_succeeded=False,
                reason="The URL hostname is an IP address, not a DNS name.",
            )

        answers: dict[str, list[object]] = {record_type: [] for record_type in _RECORD_TYPES}
        errors: list[DnsLookupError] = []
        successful_responses = 0
        for record_type in _RECORD_TYPES:
            try:
                response = self._resolver.resolve(
                    hostname, record_type, lifetime=self._timeout
                )
                answers[record_type] = list(response)
                successful_responses += 1
            except dns.resolver.NoAnswer:
                # An empty RRset is a normal DNS response, not a resolver error.
                successful_responses += 1
                continue
            except dns.resolver.NXDOMAIN as exc:
                errors.append(self._error(record_type, exc))
                return self._build_result(hostname, answers, errors, successful_responses)
            except dns.exception.Timeout as exc:
                errors.append(self._error(record_type, exc))
            except dns.resolver.NoNameservers as exc:
                errors.append(self._error(record_type, exc))
            except dns.exception.DNSException as exc:
                errors.append(self._error(record_type, exc))
            except OSError as exc:
                errors.append(self._error(record_type, exc))
            except Exception as exc:
                errors.append(self._error(record_type, exc))

        return self._build_result(hostname, answers, errors, successful_responses)

    @staticmethod
    def _error(record_type: str, exc: Exception) -> DnsLookupError:
        return DnsLookupError(
            record_type=record_type,
            error_type=type(exc).__name__,
            message=str(exc) or type(exc).__name__,
        )

    @staticmethod
    def _build_result(
        hostname: str,
        answers: dict[str, list[object]],
        errors: list[DnsLookupError],
        successful_responses: int,
    ) -> DnsAnalysisResult:
        ipv4_addresses = [
            DnsAnalyzer._value(record, "address") for record in answers["A"]
        ]
        ipv6_addresses = [
            DnsAnalyzer._value(record, "address") for record in answers["AAAA"]
        ]
        cname_targets = [
            DnsAnalyzer._dns_name(DnsAnalyzer._value(record, "target"))
            for record in answers["CNAME"]
        ]
        mail_servers = [
            DnsMailServer(
                preference=int(getattr(record, "preference", 0)),
                exchange=DnsAnalyzer._dns_name(
                    DnsAnalyzer._value(record, "exchange")
                ),
            )
            for record in answers["MX"]
        ]
        nameservers = [
            DnsAnalyzer._dns_name(DnsAnalyzer._value(record, "target"))
            for record in answers["NS"]
        ]
        txt_records = [
            DnsAnalyzer._txt_value(record) for record in answers["TXT"]
        ]
        found_records = any(answers.values())
        if errors and successful_responses:
            status = "partial"
        elif errors:
            status = "error"
        elif found_records:
            status = "ok"
        else:
            status = "no_records"
        return DnsAnalysisResult(
            hostname=hostname,
            status=status,
            resolution_succeeded=successful_responses > 0,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            cname_target=cname_targets[0] if cname_targets else None,
            mail_servers=mail_servers,
            nameservers=nameservers,
            txt_records=txt_records,
            errors=errors,
        )

    @staticmethod
    def _value(record: object, attribute: str) -> str:
        value = getattr(record, attribute, record)
        return str(value)

    @staticmethod
    def _dns_name(value: str) -> str:
        return value.rstrip(".") or "."

    @staticmethod
    def _txt_value(record: object) -> str:
        chunks = getattr(record, "strings", None)
        if chunks is not None:
            return "".join(
                chunk.decode("utf-8", errors="replace")
                if isinstance(chunk, bytes)
                else str(chunk)
                for chunk in chunks
            )
        to_text = getattr(record, "to_text", None)
        return str(to_text() if callable(to_text) else record).strip('"')
