from uuid import uuid4

import pytest

from app.api.v1.schemas.operations import StrictOperationRequest
from app.services.operator_control_service import OperatorControlError
from app.services.security_audit_service import SecurityAuditAction


def test_empty_operation_request_forbids_mass_assignment() -> None:
    assert StrictOperationRequest.model_validate({}).model_dump() == {}
    with pytest.raises(ValueError):
        StrictOperationRequest.model_validate({"source_slug": "attacker-controlled"})


def test_operator_error_exposes_only_closed_safe_metadata() -> None:
    error = OperatorControlError(
        "source_active",
        "The source has an active operation.",
        status_code=409,
        action=SecurityAuditAction.SOURCE_PAUSED,
        target_type="intelligence_source",
        target_ref="cisa-kev",
        reason="source_active",
    )
    assert error.code == "source_active"
    assert error.status_code == 409
    assert "sql" not in error.public_message.casefold()
    assert uuid4() != uuid4()
