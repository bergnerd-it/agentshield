"""Domain models for reversible pseudonymization."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from agentshield.filtering.models import FindingCategory

REVERSIBLE_CATEGORIES: frozenset[FindingCategory] = frozenset(
    {
        FindingCategory.PII_EMAIL,
        FindingCategory.PII_PHONE,
        FindingCategory.PII_IBAN,
        FindingCategory.PII_IP_ADDRESS,
        FindingCategory.PII_PERSON,
        FindingCategory.PII_ORGANIZATION,
        FindingCategory.CUSTOM_TERM,
    }
)


class CategoryPrefix(StrEnum):
    """Short prefixes for structured placeholders."""

    PII_EMAIL = "EMAIL"
    PII_PHONE = "PHONE"
    PII_IBAN = "IBAN"
    PII_IP_ADDRESS = "IP"
    PII_PERSON = "PERSON"
    PII_ORGANIZATION = "ORG"
    CUSTOM_TERM = "TERM"

    @classmethod
    def from_category(cls, category: FindingCategory) -> str:
        match category:
            case FindingCategory.PII_EMAIL:
                return cls.PII_EMAIL.value
            case FindingCategory.PII_PHONE:
                return cls.PII_PHONE.value
            case FindingCategory.PII_IBAN:
                return cls.PII_IBAN.value
            case FindingCategory.PII_IP_ADDRESS:
                return cls.PII_IP_ADDRESS.value
            case FindingCategory.PII_PERSON:
                return cls.PII_PERSON.value
            case FindingCategory.PII_ORGANIZATION:
                return cls.PII_ORGANIZATION.value
            case FindingCategory.CUSTOM_TERM:
                return cls.CUSTOM_TERM.value
            case _:
                raise ValueError(f"Category {category} is not reversible")


@dataclass(frozen=True, slots=True)
class PseudonymEntry:
    """One registered reversible pseudonym mapping."""

    placeholder: str
    original_value: str
    category: FindingCategory
    session_id: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self, current_time: datetime) -> bool:
        return current_time >= self.expires_at
