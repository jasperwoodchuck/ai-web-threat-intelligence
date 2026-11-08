"""Explainable, offline checks for domains resembling curated legitimate sites."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

import tldextract

from app.analyzers.known_domains import POPULAR_LEGITIMATE_DOMAINS

_MIN_SIMILARITY = 0.8
_MAX_EDIT_DISTANCE = 2
_CONFUSABLES = str.maketrans(
    {
        # Common digit substitutions.
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
        # Common Cyrillic and Greek lookalikes. This is a deliberately small,
        # auditable skeleton map, not a claim to cover every Unicode confusable.
        "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o",
        "р": "p", "Р": "p", "с": "c", "С": "c", "х": "x", "Х": "x",
        "у": "y", "У": "y", "і": "i", "І": "i", "ј": "j", "Ј": "j",
        "к": "k", "К": "k", "м": "m", "М": "m", "т": "t", "Т": "t",
        "в": "b", "В": "b", "н": "h", "Н": "h", "ѕ": "s", "Ѕ": "s",
        "α": "a", "Α": "a", "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p",
        "ι": "i", "Ι": "i", "κ": "k", "Κ": "k", "τ": "t", "Τ": "t",
        "χ": "x", "Χ": "x", "ν": "v", "Ν": "v", "μ": "m", "Μ": "m",
    }
)
_BRAND_ACTIONS = frozenset(
    {"account", "auth", "billing", "login", "secure", "security", "support", "verify", "verification"}
)
_PUBLIC_SUFFIX = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


@dataclass(frozen=True)
class LookalikeDomainMatch:
    intended_domain: str
    similarity: float
    edit_distance: int
    normalized_edit_distance: int
    suspicious_domain: str = ""
    technique: str = "character_edit"
    severity: str = "medium"
    evidence: str = ""
    idn: bool = False


def _decode_label(label: str) -> str:
    if label.lower().startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeEncodeError):
            return label.lower()
    return label


def _label_and_suffix(domain: str) -> tuple[str, str]:
    extracted = _PUBLIC_SUFFIX(domain.rstrip(".").lower())
    if extracted.domain:
        return _decode_label(extracted.domain), extracted.suffix.lower()
    # Unknown suffixes still get a conservative last-label boundary. Known
    # multi-label suffixes (for example co.uk) are handled by tldextract above.
    labels = domain.rstrip(".").lower().split(".")
    return (_decode_label(labels[-2]), labels[-1]) if len(labels) > 1 else ("", "")


def _skeleton(label: str) -> str:
    normalized = unicodedata.normalize("NFKC", label).casefold()
    return normalized.translate(_CONFUSABLES)


def _is_idn(domain: str) -> bool:
    return any(label.lower().startswith("xn--") for label in domain.split(".")) or any(
        not character.isascii() for character in domain
    )


def _raw_distance(candidate: str, reference: str) -> int:
    return damerau_levenshtein(
        unicodedata.normalize("NFKC", candidate).casefold(),
        unicodedata.normalize("NFKC", reference).casefold(),
    )


def _edit_technique(candidate: str, reference: str) -> tuple[str, str]:
    if len(candidate) == len(reference):
        changed = [index for index, (left, right) in enumerate(zip(candidate, reference)) if left != right]
        if len(changed) == 2:
            first, second = changed
            if second == first + 1 and candidate[first] == reference[second] and candidate[second] == reference[first]:
                return "adjacent_character_swap", f"Adjacent characters '{candidate[first]}{candidate[second]}' are swapped."
        if len(changed) == 1:
            index = changed[0]
            return "character_substitution", f"'{candidate[index]}' replaces '{reference[index]}' in the domain label."
    if len(candidate) == len(reference) + 1:
        for index, character in enumerate(candidate):
            if candidate[:index] + candidate[index + 1 :] == reference:
                if (index > 0 and candidate[index - 1] == character) or (
                    index + 1 < len(candidate) and candidate[index + 1] == character
                ):
                    return "repeated_character", f"The character '{character}' is repeated in the domain label."
                return "character_insertion", f"The extra character '{character}' is inserted in the domain label."
    if len(reference) == len(candidate) + 1:
        for index, character in enumerate(reference):
            if reference[:index] + reference[index + 1 :] == candidate:
                return "character_deletion", f"The domain label is missing '{character}' from the reference spelling."
    return "multiple_character_edits", "The domain label has multiple character edits relative to the reference."


def _confusable_evidence(candidate: str, reference: str) -> tuple[str, str] | None:
    normalized = unicodedata.normalize("NFKC", candidate).casefold()
    target = unicodedata.normalize("NFKC", reference).casefold()
    if len(normalized) != len(target):
        return None
    pairs = [(actual, expected) for actual, expected in zip(normalized, target) if actual != expected]
    if not pairs:
        return None
    if all(actual in "0134578" and _skeleton(actual) == expected for actual, expected in pairs):
        actual, expected = pairs[0]
        return "character_substitution", f"The digit '{actual}' is commonly used in place of the letter '{expected}'."
    if all(actual.translate(_CONFUSABLES) == expected for actual, expected in pairs):
        examples = ", ".join(f"'{actual}' resembles '{expected}'" for actual, expected in pairs)
        return "homoglyph_substitution", f"Visually similar Unicode characters appear in the label: {examples}."
    return None


def _make_match(
    candidate_label: str,
    reference_label: str,
    reference_domain: str,
    suspicious_domain: str,
    *,
    idn: bool,
) -> LookalikeDomainMatch | None:
    candidate = unicodedata.normalize("NFKC", candidate_label).casefold()
    reference = unicodedata.normalize("NFKC", reference_label).casefold()
    candidate_skeleton = _skeleton(candidate_label)
    reference_skeleton = _skeleton(reference_label)

    # Hyphens are considered only when removing them recreates the full known
    # brand label; mere inclusion such as paypal-example is not enough.
    if candidate.replace("-", "") == reference and candidate != reference:
        distance = candidate.count("-")
        return LookalikeDomainMatch(
            intended_domain=reference_domain,
            similarity=round(1 - distance / max(len(candidate), len(reference), 1), 2),
            edit_distance=distance,
            normalized_edit_distance=distance,
            suspicious_domain=suspicious_domain,
            technique="hyphen_insertion",
            evidence="A hyphen splits the domain label spelling of the reference domain.",
            idn=idn,
        )

    normalized_distance = damerau_levenshtein(candidate_skeleton, reference_skeleton)
    normalized_similarity = 1 - normalized_distance / max(
        len(candidate_skeleton), len(reference_skeleton), 1
    )
    raw_distance = _raw_distance(candidate, reference)
    raw_similarity = 1 - raw_distance / max(len(candidate), len(reference), 1)
    # Blend literal edit similarity with the confusable-normalized score. This
    # keeps a mapped digit or Unicode lookalike from appearing to be an exact match.
    similarity = (raw_similarity + normalized_similarity) / 2
    confusable = _confusable_evidence(candidate, reference)

    if normalized_distance == 0 and raw_distance > 0 and confusable:
        technique, evidence = confusable
    elif normalized_distance == 0 and idn and candidate_skeleton == reference_skeleton:
        technique = "homoglyph_substitution"
        evidence = "The IDN label normalizes to the same visual skeleton as the reference domain."
    elif normalized_distance == 0:
        # An exact brand label on a different public suffix is not a typo by
        # itself; do not label paypal.net as a typo of paypal.com.
        return None
    else:
        if normalized_distance > _MAX_EDIT_DISTANCE or similarity < _MIN_SIMILARITY:
            return None
        technique, evidence = _edit_technique(candidate_skeleton, reference_skeleton)

    return LookalikeDomainMatch(
        intended_domain=reference_domain,
        similarity=round(similarity, 2),
        edit_distance=raw_distance,
        normalized_edit_distance=normalized_distance,
        suspicious_domain=suspicious_domain,
        technique=technique,
        severity="medium",
        evidence=evidence,
        idn=idn,
    )


def _brand_parts(known_domains: Iterable[str]) -> list[tuple[str, str, str]]:
    brands = []
    for domain in known_domains:
        label, suffix = _label_and_suffix(domain)
        if label and suffix:
            brands.append((label, suffix, domain.lower().rstrip(".")))
    return brands


def _has_brand_action(label: str, brand: str) -> bool:
    normalized = label.casefold()
    parts = normalized.split("-")
    if brand.casefold() in parts and any(part in _BRAND_ACTIONS for part in parts):
        return True
    return any(
        normalized == f"{brand}{action}" or normalized == f"{action}{brand}"
        for action in _BRAND_ACTIONS
    )


def detect_lookalike_domain(
    registered_domain: str | None,
    known_domains: Iterable[str] = POPULAR_LEGITIMATE_DOMAINS,
    *,
    hostname: str | None = None,
    subdomain: str | None = None,
) -> LookalikeDomainMatch | None:
    """Compare PSL-derived labels to configured references without network calls."""
    if not registered_domain:
        return None

    brands = _brand_parts(tuple(known_domains))
    candidate_label, candidate_suffix = _label_and_suffix(registered_domain)
    if not candidate_label or not candidate_suffix:
        return None

    domain_idn = _is_idn(registered_domain) or bool(hostname and _is_idn(hostname))
    candidates: list[tuple[tuple[float, int, str], LookalikeDomainMatch]] = []

    for brand_label, brand_suffix, reference_domain in brands:
        if candidate_label.casefold() == brand_label.casefold() and candidate_suffix == brand_suffix:
            continue
        match = _make_match(
            candidate_label,
            brand_label,
            reference_domain,
            registered_domain.lower().rstrip("."),
            idn=domain_idn,
        )
        if match is not None:
            candidates.append(((-match.similarity, match.edit_distance, match.intended_domain), match))

    # Require both a known brand token and a security/account action term.
    # This avoids flagging unrelated labels such as "paypal-example.com".
    for brand_label, _brand_suffix, reference_domain in brands:
        if _has_brand_action(candidate_label, brand_label):
            candidates.append(
                (
                    (-1.0, 0, reference_domain),
                    LookalikeDomainMatch(
                        intended_domain=reference_domain,
                        similarity=1.0,
                        edit_distance=0,
                        normalized_edit_distance=0,
                        suspicious_domain=registered_domain.lower().rstrip("."),
                        technique="brand_action_domain",
                        severity="medium",
                        evidence="The registrable label combines the reference brand with an account or security action term.",
                        idn=domain_idn,
                    ),
                )
            )

    # Brand names in a subdomain are not the registrable owner. Treat an exact
    # or similarly altered reference label there as a lower-confidence
    # impersonation signal; a normal subdomain of the actual brand is excluded.
    if hostname and subdomain:
        normalized_registered = registered_domain.lower().rstrip(".")
        for brand_label, _brand_suffix, reference_domain in brands:
            if normalized_registered == reference_domain:
                continue
            for sub_label in subdomain.lower().split("."):
                parts = sub_label.split("-")
                brand_part = next((part for part in parts if part == brand_label.casefold()), None)
                sub_match = _make_match(
                    sub_label,
                    brand_label,
                    reference_domain,
                    hostname.lower().rstrip("."),
                    idn=domain_idn,
                )
                if brand_part or _has_brand_action(sub_label, brand_label) or sub_match:
                    evidence = (
                        f"'{sub_label}' uses the reference brand in a subdomain, "
                        if brand_part
                        else f"Subdomain label '{sub_label}' resembles the reference brand, "
                    )
                    candidates.append(
                        (
                            (-1.0, sub_match.edit_distance if sub_match else 0, reference_domain),
                            LookalikeDomainMatch(
                                intended_domain=reference_domain,
                                similarity=sub_match.similarity if sub_match else 1.0,
                                edit_distance=sub_match.edit_distance if sub_match else 0,
                                normalized_edit_distance=sub_match.normalized_edit_distance if sub_match else 0,
                                suspicious_domain=hostname.lower().rstrip("."),
                                technique="misleading_subdomain",
                                severity="medium",
                                evidence=f"{evidence}but the registrable domain is {normalized_registered}.",
                                idn=domain_idn,
                            ),
                        )
                    )
                    break

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
