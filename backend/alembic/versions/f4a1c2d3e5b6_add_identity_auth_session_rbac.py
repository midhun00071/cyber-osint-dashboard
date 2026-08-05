"""add identity authentication session and rbac

Revision ID: f4a1c2d3e5b6
Revises: e91f4c2a7b60
Create Date: 2026-08-05 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f4a1c2d3e5b6"
down_revision: str | Sequence[str] | None = "e91f4c2a7b60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "auth_users",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("account_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("session_version", sa.BigInteger(), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("char_length(btrim(display_name)) BETWEEN 1 AND 160", name="ck_auth_users_display_name_length"),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_auth_users_status_allowed"),
        sa.CheckConstraint("(status = 'active' AND disabled_at IS NULL) OR (status = 'disabled' AND disabled_at IS NOT NULL)", name="ck_auth_users_status_disabled_at_consistency"),
        sa.CheckConstraint("session_version > 0", name="ck_auth_users_session_version_positive"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_auth_users_updated_at_order"),
        sa.CheckConstraint("account_expires_at IS NULL OR account_expires_at > created_at", name="ck_auth_users_account_expiry_order"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_users"),
        sa.UniqueConstraint("public_id", name="uq_auth_users_public_id"),
    )

    op.create_table(
        "auth_identities",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("provider_key", sa.String(40), nullable=False),
        sa.Column("subject_key", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("provider_key ~ '^[a-z][a-z0-9_]{0,39}$'", name="ck_auth_identities_provider_key_format"),
        sa.CheckConstraint("char_length(btrim(subject_key)) BETWEEN 1 AND 80", name="ck_auth_identities_subject_key_length"),
        sa.ForeignKeyConstraint(["user_id"], ["auth_users.id"], name="fk_auth_identities_user_id_auth_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_identities"),
        sa.UniqueConstraint("provider_key", "subject_key", name="uq_auth_identities_provider_subject"),
        sa.UniqueConstraint("user_id", "provider_key", name="uq_auth_identities_user_provider"),
    )

    op.create_table(
        "auth_local_credentials",
        sa.Column("identity_id", sa.BigInteger(), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("password_hash LIKE '$argon2id$%'", name="ck_auth_local_credentials_argon2id_prefix"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_auth_local_credentials_updated_at_order"),
        sa.ForeignKeyConstraint(["identity_id"], ["auth_identities.id"], name="fk_auth_local_credentials_identity_id_auth_identities", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("identity_id", name="pk_auth_local_credentials"),
    )

    op.create_table(
        "auth_user_roles",
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("role_key", sa.String(40), nullable=False),
        sa.Column("assigned_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role_key IN ('viewer', 'analyst', 'ingestion_operator', 'administrator')", name="ck_auth_user_roles_role_key_allowed"),
        sa.CheckConstraint("updated_at >= assigned_at", name="ck_auth_user_roles_updated_at_order"),
        sa.ForeignKeyConstraint(["user_id"], ["auth_users.id"], name="fk_auth_user_roles_user_id_auth_users", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assigned_by_user_id"], ["auth_users.id"], name="fk_auth_user_roles_assigned_by_user_id_auth_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("user_id", name="pk_auth_user_roles"),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column("user_session_version", sa.BigInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_sessions_token_hash_format"),
        sa.CheckConstraint("csrf_token_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_sessions_csrf_token_hash_format"),
        sa.CheckConstraint("user_session_version > 0", name="ck_auth_sessions_user_session_version_positive"),
        sa.CheckConstraint("expires_at > issued_at AND absolute_expires_at >= expires_at", name="ck_auth_sessions_expiry_order"),
        sa.CheckConstraint("created_at >= issued_at AND updated_at >= created_at", name="ck_auth_sessions_timestamp_order"),
        sa.CheckConstraint("rotated_at IS NULL OR (rotated_at >= issued_at AND rotated_at <= absolute_expires_at)", name="ck_auth_sessions_rotated_at_order"),
        sa.CheckConstraint("(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)", name="ck_auth_sessions_revocation_shape"),
        sa.CheckConstraint("revoked_at IS NULL OR (revoked_at >= issued_at AND revoked_at <= updated_at)", name="ck_auth_sessions_revoked_at_order"),
        sa.CheckConstraint("revocation_reason IS NULL OR revocation_reason IN ('logout', 'refresh', 'password_change', 'account_disabled', 'role_changed', 'admin_revocation', 'session_limit')", name="ck_auth_sessions_revocation_reason_allowed"),
        sa.ForeignKeyConstraint(["user_id"], ["auth_users.id"], name="fk_auth_sessions_user_id_auth_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_sessions"),
        sa.UniqueConstraint("public_id", name="uq_auth_sessions_public_id"),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
    )
    op.create_index("ix_auth_sessions_user_active_expiry", "auth_sessions", ["user_id", "revoked_at", "expires_at"])
    op.create_index("ix_auth_sessions_retention_expiry", "auth_sessions", ["absolute_expires_at", "id"])

    op.create_table(
        "auth_login_throttles",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("login_key_hash", sa.String(64), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("login_key_hash ~ '^[0-9a-f]{64}$'", name="ck_auth_login_throttles_login_key_hash_format"),
        sa.CheckConstraint("failure_count BETWEEN 0 AND 1000", name="ck_auth_login_throttles_failure_count_bounded"),
        sa.CheckConstraint("updated_at >= window_started_at", name="ck_auth_login_throttles_updated_at_order"),
        sa.CheckConstraint("blocked_until IS NULL OR blocked_until >= window_started_at", name="ck_auth_login_throttles_blocked_until_order"),
        sa.PrimaryKeyConstraint("id", name="pk_auth_login_throttles"),
        sa.UniqueConstraint("login_key_hash", name="uq_auth_login_throttles_login_key_hash"),
    )
    op.create_index("ix_auth_login_throttles_blocked_until", "auth_login_throttles", ["blocked_until"])
    op.create_index("ix_auth_login_throttles_window_updated", "auth_login_throttles", ["window_started_at", "updated_at"])


def downgrade() -> None:
    op.drop_table("auth_login_throttles")
    op.drop_table("auth_sessions")
    op.drop_table("auth_user_roles")
    op.drop_table("auth_local_credentials")
    op.drop_table("auth_identities")
    op.drop_table("auth_users")
