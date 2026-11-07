from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatIntelStatus(StrEnum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"


class ThreatIntelResult(BaseModel):
    status: ThreatIntelStatus
    matched: bool | None
    source: str
    indicator: str
    match_scope: str | None = None
    threat_type: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence: dict[str, object] = Field(default_factory=dict)
    reference: str | None = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None


class ThreatIntelProvider(ABC):
    """Lookup an already-normalized URL or domain in one threat-intelligence source."""

    @abstractmethod
    def lookup(self, indicator: str) -> ThreatIntelResult:
        """Return normalized intelligence evidence for the indicator."""
