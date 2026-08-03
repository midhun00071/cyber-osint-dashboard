from __future__ import annotations

import ast
import inspect

import pytest

from app.ingestion.services.operational_persistence_service import (
    OperationalValidationError,
    OperationalPersistenceService,
    _validate_cycle_outcome,
)
from app.orchestration.persistence import OrchestrationPersistenceAdapter
from app.orchestration.contracts import PersistenceAdapter


def test_adapter_owns_transactions_and_service_still_does_not() -> None:
    adapter_tree = ast.parse(inspect.getsource(inspect.getmodule(OrchestrationPersistenceAdapter)))
    service_tree = ast.parse(inspect.getsource(inspect.getmodule(OperationalPersistenceService)))
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "begin"
        for node in ast.walk(adapter_tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"commit", "rollback", "close", "begin"}
        for node in ast.walk(service_tree)
    )


@pytest.mark.parametrize(
    "arguments",
    (
        dict(status="success", expected=2, started=2, completed=1, successful=1, non_successful=0),
        dict(status="success", expected=1, started=1, completed=1, successful=0, non_successful=1),
        dict(status="partial", expected=1, started=1, completed=1, successful=1, non_successful=0),
        dict(status="failed", expected=1, started=1, completed=1, successful=1, non_successful=0),
        dict(status="cancelled", expected=1, started=1, completed=1, successful=1, non_successful=0),
    ),
)
def test_cycle_outcome_validation_rejects_false_terminal_evidence(arguments) -> None:
    with pytest.raises(OperationalValidationError):
        _validate_cycle_outcome(**arguments)


def test_cycle_outcome_validation_accepts_truthful_terminal_evidence() -> None:
    _validate_cycle_outcome(
        status="success",
        expected=1,
        started=1,
        completed=1,
        successful=1,
        non_successful=0,
    )
    _validate_cycle_outcome(
        status="partial",
        expected=2,
        started=2,
        completed=2,
        successful=1,
        non_successful=1,
    )
    _validate_cycle_outcome(
        status="failed",
        expected=1,
        started=1,
        completed=1,
        successful=0,
        non_successful=1,
    )
    _validate_cycle_outcome(
        status="cancelled",
        expected=1,
        started=1,
        completed=1,
        successful=0,
        non_successful=1,
    )
    _validate_cycle_outcome(
        status="cancelled",
        expected=1,
        started=0,
        completed=0,
        successful=0,
        non_successful=0,
    )


def test_persistence_adapter_contains_no_raw_sql_or_external_client_logic() -> None:
    source = inspect.getsource(inspect.getmodule(OrchestrationPersistenceAdapter))
    assert "text(" not in source
    assert "httpx" not in source
    assert "requests" not in source


def test_adapter_exposes_evidence_and_pending_recovery_protocols() -> None:
    adapter = OrchestrationPersistenceAdapter()
    assert isinstance(adapter, PersistenceAdapter)
    assert callable(adapter.read_cycle_evidence)
    assert callable(adapter.abandon_pending_progress)
