"""In-memory session-scoped reversible pseudonym vault."""

import hashlib
import re
import threading
from datetime import UTC, datetime, timedelta

from agentshield.filtering.models import FindingCategory
from agentshield.pseudonyms.models import (
    REVERSIBLE_CATEGORIES,
    CategoryPrefix,
    PseudonymEntry,
)

PLACEHOLDER_REGEX = re.compile(r"<AS:[A-Z_]+:[a-zA-Z0-9_-]+:\d{4}>")


class InMemoryPseudonymVault:
    """Thread-safe in-memory vault for reversible pseudonyms with bounded TTL."""

    def __init__(self, default_ttl_seconds: int = 3600) -> None:
        self.default_ttl = timedelta(seconds=default_ttl_seconds)
        self._lock = threading.Lock()
        # session_id -> (category, original_value) -> PseudonymEntry
        self._by_value: dict[str, dict[tuple[FindingCategory, str], PseudonymEntry]] = {}
        # session_id -> placeholder -> PseudonymEntry
        self._by_placeholder: dict[str, dict[str, PseudonymEntry]] = {}
        # session_id -> category -> counter
        self._counters: dict[str, dict[FindingCategory, int]] = {}

    @staticmethod
    def _sanitize_session_id(session_id: str) -> str:
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]

    def get_or_create(
        self,
        *,
        session_id: str,
        original_value: str,
        category: FindingCategory,
        input_context: str | None = None,
        now: datetime | None = None,
    ) -> str:
        """Get existing placeholder or create a new collision-resistant one."""
        if category.is_secret:
            raise ValueError(f"Secrets ({category.value}) can never be pseudonymized reversibly")
        if category not in REVERSIBLE_CATEGORIES:
            raise ValueError(f"Category {category.value} is not eligible for reversible mapping")

        current_time = now or datetime.now(UTC)

        with self._lock:
            session_values = self._by_value.setdefault(session_id, {})
            session_placeholders = self._by_placeholder.setdefault(session_id, {})
            session_counters = self._counters.setdefault(session_id, {})

            key = (category, original_value)
            existing = session_values.get(key)
            if existing is not None and not existing.is_expired(current_time):
                return existing.placeholder

            # Generate new placeholder with collision avoidance
            prefix = CategoryPrefix.from_category(category)
            sess_prefix = self._sanitize_session_id(session_id)

            while True:
                counter = session_counters.get(category, 0) + 1
                session_counters[category] = counter
                placeholder = f"<AS:{prefix}:{sess_prefix}:{counter:04d}>"

                # Check collisions:
                # 1. Not already registered in this session
                if placeholder in session_placeholders:
                    continue
                # 2. Not already appearing verbatim in input context
                if input_context is not None and placeholder in input_context:
                    continue
                break

            entry = PseudonymEntry(
                placeholder=placeholder,
                original_value=original_value,
                category=category,
                session_id=session_id,
                created_at=current_time,
                expires_at=current_time + self.default_ttl,
            )
            session_values[key] = entry
            session_placeholders[placeholder] = entry
            return placeholder

    def rehydrate(
        self,
        *,
        session_id: str,
        placeholder: str,
        now: datetime | None = None,
    ) -> str | None:
        """Resolve an exact issued placeholder for an active session."""
        current_time = now or datetime.now(UTC)

        with self._lock:
            session_placeholders = self._by_placeholder.get(session_id)
            if not session_placeholders:
                return None

            entry = session_placeholders.get(placeholder)
            if entry is None or entry.is_expired(current_time):
                return None

            return entry.original_value

    def has_session_mappings(self, session_id: str) -> bool:
        """Check if any mappings exist for the given session."""
        with self._lock:
            return bool(self._by_placeholder.get(session_id))

    def cleanup_expired(self, now: datetime | None = None) -> int:
        """Purge expired entries across all sessions. Return count of purged entries."""
        current_time = now or datetime.now(UTC)
        purged = 0

        with self._lock:
            for session_id in list(self._by_placeholder.keys()):
                placeholders = self._by_placeholder[session_id]
                values = self._by_value[session_id]

                expired_keys: list[str] = [
                    ph for ph, entry in placeholders.items() if entry.is_expired(current_time)
                ]
                for ph in expired_keys:
                    entry = placeholders.pop(ph)
                    values.pop((entry.category, entry.original_value), None)
                    purged += 1

                if not placeholders:
                    self._by_placeholder.pop(session_id, None)
                    self._by_value.pop(session_id, None)
                    self._counters.pop(session_id, None)

        return purged

    def clear_session(self, session_id: str) -> None:
        """Explicitly clear all mappings for a specific session."""
        with self._lock:
            self._by_placeholder.pop(session_id, None)
            self._by_value.pop(session_id, None)
            self._counters.pop(session_id, None)

    def clear_all(self) -> None:
        """Clear all sessions and mappings."""
        with self._lock:
            self._by_placeholder.clear()
            self._by_value.clear()
            self._counters.clear()
