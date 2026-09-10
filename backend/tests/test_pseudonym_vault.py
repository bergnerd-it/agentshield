"""Unit tests for InMemoryPseudonymVault."""

from datetime import UTC, datetime, timedelta

import pytest

from agentshield.filtering.models import FindingCategory
from agentshield.pseudonyms.models import REVERSIBLE_CATEGORIES
from agentshield.pseudonyms.vault import InMemoryPseudonymVault


def test_vault_rejects_all_secret_categories() -> None:
    vault = InMemoryPseudonymVault()
    secret_categories = [cat for cat in FindingCategory if cat.is_secret]
    assert len(secret_categories) > 0

    for cat in secret_categories:
        with pytest.raises(ValueError, match=r"Secrets .* can never be pseudonymized"):
            vault.get_or_create(
                session_id="sess_123",
                original_value="synth-secret-val",
                category=cat,
            )


def test_vault_allows_all_reversible_categories() -> None:
    vault = InMemoryPseudonymVault()
    for cat in REVERSIBLE_CATEGORIES:
        placeholder = vault.get_or_create(
            session_id="sess_123",
            original_value=f"sample_{cat.value}",
            category=cat,
        )
        assert placeholder.startswith("<AS:")
        assert placeholder.endswith(">")
        rehydrated = vault.rehydrate(session_id="sess_123", placeholder=placeholder)
        assert rehydrated == f"sample_{cat.value}"


def test_consistency_within_same_session() -> None:
    vault = InMemoryPseudonymVault()
    p1 = vault.get_or_create(
        session_id="sess_abc",
        original_value="Alice Smith",
        category=FindingCategory.PII_PERSON,
    )
    p2 = vault.get_or_create(
        session_id="sess_abc",
        original_value="Alice Smith",
        category=FindingCategory.PII_PERSON,
    )
    assert p1 == p2

    p3 = vault.get_or_create(
        session_id="sess_abc",
        original_value="Bob Jones",
        category=FindingCategory.PII_PERSON,
    )
    assert p1 != p3


def test_session_isolation() -> None:
    vault = InMemoryPseudonymVault()
    p_sess1 = vault.get_or_create(
        session_id="session_alpha",
        original_value="Alice Smith",
        category=FindingCategory.PII_PERSON,
    )
    p_sess2 = vault.get_or_create(
        session_id="session_beta",
        original_value="Alice Smith",
        category=FindingCategory.PII_PERSON,
    )
    assert p_sess1 != p_sess2

    # Rehydration in session_alpha cannot resolve session_beta placeholder
    assert vault.rehydrate(session_id="session_alpha", placeholder=p_sess2) is None
    assert vault.rehydrate(session_id="session_beta", placeholder=p_sess1) is None
    assert vault.rehydrate(session_id="session_alpha", placeholder=p_sess1) == "Alice Smith"
    assert vault.rehydrate(session_id="session_beta", placeholder=p_sess2) == "Alice Smith"


def test_collision_avoidance() -> None:
    vault = InMemoryPseudonymVault()
    import hashlib

    sess_prefix = hashlib.sha256(b"sess1234").hexdigest()[:8]
    # If the input text already contains the candidate placeholder
    text_with_collision = f"Contact <AS:PERSON:{sess_prefix}:0001> for details"
    p = vault.get_or_create(
        session_id="sess1234",
        original_value="Charlie",
        category=FindingCategory.PII_PERSON,
        input_context=text_with_collision,
    )
    # The vault should have detected the collision and chosen counter 0002
    assert p != f"<AS:PERSON:{sess_prefix}:0001>"
    assert p == f"<AS:PERSON:{sess_prefix}:0002>"


def test_ttl_expiration_and_cleanup() -> None:
    vault = InMemoryPseudonymVault(default_ttl_seconds=60)
    t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)

    p = vault.get_or_create(
        session_id="sess_ttl",
        original_value="secret_project_omega",
        category=FindingCategory.CUSTOM_TERM,
        now=t0,
    )
    # At t0 + 30s: still valid
    assert (
        vault.rehydrate(session_id="sess_ttl", placeholder=p, now=t0 + timedelta(seconds=30))
        == "secret_project_omega"
    )

    # At t0 + 61s: expired
    t_expired = t0 + timedelta(seconds=61)
    assert vault.rehydrate(session_id="sess_ttl", placeholder=p, now=t_expired) is None

    # Cleanup removes it
    purged = vault.cleanup_expired(now=t_expired)
    assert purged == 1
    assert not vault.has_session_mappings("sess_ttl")


def test_rehydrate_tampered_placeholder_returns_none() -> None:
    vault = InMemoryPseudonymVault()
    vault.get_or_create(
        session_id="sess_1",
        original_value="user@example.com",
        category=FindingCategory.PII_EMAIL,
    )
    assert vault.rehydrate(session_id="sess_1", placeholder="<AS:EMAIL:sess_1:9999>") is None
    assert vault.rehydrate(session_id="sess_1", placeholder="<AS:UNKNOWN:foo:0001>") is None
    assert vault.rehydrate(session_id="sess_1", placeholder="plain text") is None
