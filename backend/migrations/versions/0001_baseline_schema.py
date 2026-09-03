"""Baseline schema for settings, policies, integrations, and audit events.

Revision ID: 0001_baseline_schema
Revises:
Create Date: 2026-09-03 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_baseline_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. app_settings
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    # 2. security_policies
    op.create_table(
        "security_policies",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("rules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_policies_profile", "security_policies", ["profile"], unique=False)

    # 3. integration_configs
    op.create_table(
        "integration_configs",
        sa.Column("agent_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="not_configured"),
        sa.Column("last_backup_path", sa.String(length=512), nullable=True),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("agent_type"),
    )

    # 4. audit_events
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("agent", sa.String(length=64), nullable=True),
        sa.Column("project", sa.String(length=128), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("endpoint", sa.String(length=128), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=True),
        sa.Column("finding_counts_json", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"], unique=False)
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"], unique=False)
    op.create_index("ix_audit_events_session_id", "audit_events", ["session_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_events_session_id", table_name="audit_events")
    op.drop_index("ix_audit_events_request_id", table_name="audit_events")
    op.drop_index("ix_audit_events_timestamp", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_table("integration_configs")

    op.drop_index("ix_security_policies_profile", table_name="security_policies")
    op.drop_table("security_policies")

    op.drop_table("app_settings")
