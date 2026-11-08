from abc import ABC, abstractmethod

from app.models.message import AIExplanation


class AIProvider(ABC):
    @abstractmethod
    def explain(
        self,
        message: str,
        deterministic_evidence: list[dict[str, str]],
        url_intelligence: list[dict[str, object]],
        semantic: bool = False,
        url_evidence: list[dict[str, object]] | None = None,
    ) -> AIExplanation:
        """Return an advisory explanation; never an authoritative verdict."""
