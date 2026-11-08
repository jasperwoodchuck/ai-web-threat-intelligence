"""Deterministic extraction and scam-language signals for untrusted messages."""

import re

from app.models.message import MessageIndicator

MAX_MESSAGE_LENGTH = 20_000
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")
_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("urgency", r"\b(urgent|immediately|within\s+\d+\s+(?:minutes?|hours?)|act\s+now|expires?\s+today|final\s+warning)\b", "high", "The message pressures the recipient to act quickly."),
    ("payment_request", r"\b(pay|payment|wire|transfer|send\s+(?:money|funds)|gift\s+cards?|crypto(?:currency)?|bitcoin|fee\s+of|invoice\s+due)\b", "high", "The message requests or discusses payment."),
    ("credential_request", r"\b(password|passcode|one[- ]time\s+(?:password|code)|\botp\b|verification\s+code|login\s+credentials|security\s+code)\b", "high", "The message refers to passwords, credentials, or one-time codes."),
    ("sensitive_information_request", r"\b(social\s+security|\bssn\b|bank\s+details|card\s+(?:number|details)|date\s+of\s+birth|private\s+key|seed\s+phrase|identity\s+documents?)\b", "high", "The message requests or refers to sensitive personal or financial information."),
    ("impersonation", r"\b(we\s+are\s+(?:your\s+)?(?:bank|banking|it\s+support|technical\s+support|government|police|tax\s+office)|(?:bank|paypal|microsoft|apple|amazon|irs|tax\s+office)\s+(?:security|support|team|department)|on\s+behalf\s+of\s+(?:your\s+)?(?:bank|company|government))\b", "high", "The sender claims an organizational or authority identity that has not been verified."),
)


class MessageAnalyzer:
    def analyze(self, message: str) -> dict[str, list]:
        text = message.strip()
        urls = list(dict.fromkeys(self._clean_url(match) for match in _URL.findall(text)))
        urls = [url for url in urls if url]
        emails = list(dict.fromkeys(_EMAIL.findall(text)))
        phones = list(dict.fromkeys(self._normalize_phone(match) for match in _PHONE.findall(text)))
        indicators: list[MessageIndicator] = []
        for category, pattern, severity, description in _PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                evidence = text[max(0, match.start() - 45):min(len(text), match.end() + 45)].replace("\n", " ")
                indicators.append(MessageIndicator(category=category, severity=severity, description=description, evidence=evidence))
                break
        if urls:
            indicators.append(MessageIndicator(category="suspicious_link_present", severity="medium", description="The message contains a link that has not been independently verified.", evidence=", ".join(urls)))
        if emails or phones:
            indicators.append(MessageIndicator(category="contact_details_present", severity="info", description="Contact details are present but have not been verified as belonging to the claimed sender.", evidence=", ".join(emails + phones)))
        groups = {
            "urgency_indicators": {"urgency"},
            "payment_request_indicators": {"payment_request"},
            "sensitive_information_indicators": {"credential_request", "sensitive_information_request"},
            "impersonation_indicators": {"impersonation"},
            "suspicious_contact_indicators": {"contact_details_present", "suspicious_link_present"},
        }
        result: dict[str, list] = {
            "extracted_urls": urls,
            "extracted_email_addresses": emails,
            "extracted_phone_numbers": phones,
            "deterministic_indicators": indicators,
            "social_engineering_indicators": [item for item in indicators if item.category in {"urgency", "payment_request", "credential_request", "sensitive_information_request", "impersonation"}],
        }
        result.update({field: [item for item in indicators if item.category in categories] for field, categories in groups.items()})
        return result

    @staticmethod
    def _clean_url(value: str) -> str:
        return value.rstrip(".,!?;:)]}")

    @staticmethod
    def _normalize_phone(value: str) -> str:
        return re.sub(r"\s+", " ", value.strip())
