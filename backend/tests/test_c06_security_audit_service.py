from uuid import uuid4
import pytest

from app.services.security_audit_service import SecurityAuditAction, SecurityAuditService


class FakeSession:
    def __init__(self): self.added = None; self.flushes = 0
    def add(self, value): self.added = value
    def flush(self): self.flushes += 1


def test_security_audit_is_closed_correlated_and_secret_free() -> None:
    session = FakeSession()
    correlation = uuid4()
    event = SecurityAuditService(session).append(action=SecurityAuditAction.AUTH_LOGIN_FAILED, actor_type="service", actor_ref="security-service", target_type="authentication", target_ref="login_attempt", outcome="failed", correlation_id=correlation, safe_detail={"reason": "invalid_credentials"})
    assert event.correlation_id == str(correlation)
    assert event.action == "auth.login.failed"
    assert "password" not in repr(event.safe_detail).lower()
    assert session.flushes == 1
    assert not hasattr(session, "commit_calls")


def test_audit_rejects_free_form_actions_and_details() -> None:
    with pytest.raises(ValueError):
        SecurityAuditService(FakeSession()).append(action="custom.action", actor_type="system", actor_ref="system", target_type="system", target_ref="system", outcome="success", correlation_id=uuid4())
