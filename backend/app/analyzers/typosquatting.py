"""Explainable, offline detection of domains resembling curated popular sites."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.analyzers.known_domains import POPULAR_LEGITIMATE_DOMAINS

_MIN_SIMILARITY = 0.8
_MAX_EDIT_DISTANCE = 2
_CONFUSABLES = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
)


@dataclass(frozen=True)
class LookalikeDomainMatch:
    intended_domain: str
    similarity: float
    edit_distance: int
    normalized_edit_distance: int


def detect_lookalike_domain(
    registered_domain: str | None,
    known_domains: Iterable[str] = POPULAR_LEGITIMATE_DOMAINS,
) -> LookalikeDomainMatch | None:
    """Return the closest sufficiently similar same-suffix registered domain."""
    if not registered_domain:
        return None

    domain = registered_domain.rstrip(".").lower()
    if domain.count(".") < 1:
        return None
    label, suffix = domain.split(".", maxsplit=1)
    if not label or not suffix:
        return None

    candidates: list[
        tuple[tuple[float, int, int, str], LookalikeDomainMatch]
    ] = []
    for known in known_domains:
        canonical = known.rstrip(".").lower()
        if canonical == domain or "." not in canonical:
            continue
        known_label, known_suffix = canonical.split(".", maxsplit=1)
        if suffix != known_suffix or label == known_label:
            continue

        raw_distance = damerau_levenshtein(label, known_label)
        normalized_distance = damerau_levenshtein(
            label.translate(_CONFUSABLES), known_label.translate(_CONFUSABLES)
        )
        similarity = 1 - normalized_distance / max(
            len(label.translate(_CONFUSABLES)),
            len(known_label.translate(_CONFUSABLES)),
        )
        if raw_distance > _MAX_EDIT_DISTANCE or similarity < _MIN_SIMILARITY:
            continue

        match = LookalikeDomainMatch(
            intended_domain=canonical,
            similarity=round(similarity, 2),
            edit_distance=raw_distance,
            normalized_edit_distance=normalized_distance,
        )
        # Prefer the highest similarity, then the smallest raw edit distance;
        # domain name is a stable tie-breaker if several candidates are equal.
        candidates.append(
            ((-similarity, raw_distance, normalized_distance, canonical), match)
        )

    return min(candidates, key=lambda item: item[0])[1] if candidates else None


def damerau_levenshtein(left: str, right: str) -> int:
    """Compute edit distance including adjacent-character transpositions."""
    rows = len(left) + 1
    columns = len(right) + 1
    distance = [[0] * columns for _ in range(rows)]
    for row in range(rows):
        distance[row][0] = row
    for column in range(columns):
        distance[0][column] = column

    for row in range(1, rows):
        for column in range(1, columns):
            cost = 0 if left[row - 1] == right[column - 1] else 1
            distance[row][column] = min(
                distance[row - 1][column] + 1,
                distance[row][column - 1] + 1,
                distance[row - 1][column - 1] + cost,
            )
            if (
                row > 1
                and column > 1
                and left[row - 1] == right[column - 2]
                and left[row - 2] == right[column - 1]
            ):
                distance[row][column] = min(
                    distance[row][column], distance[row - 2][column - 2] + cost
                )
    return distance[-1][-1]
