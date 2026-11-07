from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace

import dns.exception
import dns.resolver

from app.analyzers.dns import DnsAnalyzer


class FakeResolver:
    def __init__(
        self,
        *,
        records: Mapping[str, list[object]] | None = None,
        errors: Mapping[str, Exception] | None = None,
    ) -> None:
        self.records = records or {}
        self.errors = errors or {}
        self.queries: list[tuple[str, str, float]] = []

    def resolve(self, hostname: str, record_type: str, lifetime: float) -> list[object]:
        self.queries.append((hostname, record_type, lifetime))
        error = self.errors.get(record_type)
        if error is not None:
            raise error
        return self.records.get(record_type, [])


def test_dns_analyzer_collects_supported_record_types() -> None:
    resolver = FakeResolver(
        records={
            "A": [SimpleNamespace(address="192.0.2.10")],
            "AAAA": [SimpleNamespace(address="2001:db8::10")],
            "CNAME": [SimpleNamespace(target="alias.example.test.")],
            "MX": [
                SimpleNamespace(preference=10, exchange="mail.example.test.")
            ],
            "NS": [SimpleNamespace(target="ns1.example.test.")],
            "TXT": [SimpleNamespace(strings=(b"v=spf1 ", b"-all"))],
        }
    )

    result = DnsAnalyzer(resolver=resolver, timeout=0.75).analyze("example.test")

    assert result.status == "ok"
    assert result.resolution_succeeded is True
    assert result.ipv4_addresses == ["192.0.2.10"]
    assert result.ipv6_addresses == ["2001:db8::10"]
    assert result.cname_target == "alias.example.test"
    assert [item.model_dump() for item in result.mail_servers] == [
        {"preference": 10, "exchange": "mail.example.test"}
    ]
    assert result.nameservers == ["ns1.example.test"]
    assert result.txt_records == ["v=spf1 -all"]
    assert {query[1] for query in resolver.queries} == {
        "A", "AAAA", "CNAME", "MX", "NS", "TXT"
    }
    assert all(
        query[0] == "example.test" and query[2] == 0.75
        for query in resolver.queries
    )


def test_nxdomain_is_returned_as_a_structured_error() -> None:
    resolver = FakeResolver(errors={"A": dns.resolver.NXDOMAIN()})

    result = DnsAnalyzer(resolver=resolver).analyze("missing.example.test")

    assert result.status == "error"
    assert result.resolution_succeeded is False
    assert result.errors[0].record_type == "A"
    assert result.errors[0].error_type == "NXDOMAIN"
    assert [query[1] for query in resolver.queries] == ["A"]


def test_timeout_is_returned_as_a_structured_error() -> None:
    resolver = FakeResolver(
        errors={
            record_type: dns.exception.Timeout("lookup timed out")
            for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
        }
    )

    result = DnsAnalyzer(resolver=resolver).analyze("slow.example.test")

    assert result.status == "error"
    assert result.resolution_succeeded is False
    assert len(result.errors) == 6
    assert all(error.error_type == "Timeout" for error in result.errors)


def test_ip_hostname_does_not_trigger_dns_queries() -> None:
    resolver = FakeResolver()

    result = DnsAnalyzer(resolver=resolver).analyze("192.0.2.10")

    assert result.status == "not_applicable"
    assert result.resolution_succeeded is False
    assert resolver.queries == []


def test_no_records_is_distinct_from_dns_resolution_failure() -> None:
    result = DnsAnalyzer(resolver=FakeResolver()).analyze("empty.example.test")

    assert result.status == "no_records"
    assert result.resolution_succeeded is True
