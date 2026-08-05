"""One-time local administrator bootstrap; never invoked by application startup."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from getpass import getpass
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_session_factory
from app.models import AuthIdentity, AuthLocalCredential, AuthUser, AuthUserRole
from app.security.contracts import RoleKey
from app.security.identity import LOCAL_PROVIDER_KEY, canonicalize_local_username
from app.security.passwords import hash_password
from app.services.security_audit_service import SecurityAuditAction, SecurityAuditService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create the first local administrator only when no users exist.")
    parser.add_argument("--username", required=True, help="Bounded local username; never a password.")
    parser.add_argument("--display-name", required=True, help="Administrator display name.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    username = canonicalize_local_username(args.username)
    display_name = args.display_name if isinstance(args.display_name, str) else ""
    if username is None or display_name != display_name.strip() or not 1 <= len(display_name) <= 160:
        print("Bootstrap could not be completed safely.")
        return 2
    session = get_session_factory()()
    try:
        session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
        existing = session.execute(select(func.count(AuthUser.id))).scalar_one()
        if existing != 0:
            print("Bootstrap refused because an application user already exists.")
            session.rollback()
            return 3
        password = getpass("Password: ")
        confirmation = getpass("Confirm password: ")
        if password != confirmation:
            print("Bootstrap could not be completed safely.")
            session.rollback()
            return 2
        now = datetime.now(UTC)
        user = AuthUser(display_name=display_name, status="active", session_version=1, created_at=now, updated_at=now)
        session.add(user)
        session.flush()
        identity = AuthIdentity(user_id=user.id, provider_key=LOCAL_PROVIDER_KEY, subject_key=username, created_at=now)
        session.add(identity)
        session.flush()
        session.add(AuthLocalCredential(identity_id=identity.id, password_hash=hash_password(password), password_changed_at=now, created_at=now, updated_at=now))
        session.add(AuthUserRole(user_id=user.id, role_key=RoleKey.ADMINISTRATOR.value, assigned_by_user_id=None, assigned_at=now, updated_at=now))
        session.flush()
        SecurityAuditService(session).append(action=SecurityAuditAction.SYSTEM_BOOTSTRAP_ADMIN, actor_type="system", actor_ref="bootstrap-cli", target_type="auth_user", target_ref=str(user.public_id), outcome="success", correlation_id=uuid4(), occurred_at=now)
        session.commit()
        print("The first local administrator was created.")
        return 0
    except (SQLAlchemyError, ValueError, RuntimeError):
        session.rollback()
        print("Bootstrap could not be completed safely.")
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
