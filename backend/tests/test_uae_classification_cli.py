from __future__ import annotations

from io import StringIO

import pytest

from app.processing import uae_classification_cli
from app.processing.uae_classification_service import (
    UaeClassificationCounts,
    UaeClassificationServiceError,
)


class FakeSession:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class FakeService:
    def __init__(self, session: FakeSession, *, fail: bool = False):
        self.session = session
        self.fail = fail
        self.calls: list[tuple[int, bool]] = []

    def classify_existing(self, *, max_items: int, apply: bool = False):
        self.calls.append((max_items, apply))
        if self.fail:
            raise UaeClassificationServiceError("postgresql://private-password")
        return UaeClassificationCounts(
            processed=max_items,
            updated=2 if apply else 0,
            would_update=0 if apply else 2,
            unchanged=3,
            skipped_protected=1,
            failed=0,
        )


def run_cli(argv, service: FakeService | None = None):
    session = FakeSession()
    active_service = service or FakeService(session)
    stdout = StringIO()
    stderr = StringIO()
    code = uae_classification_cli.run_classification(
        max_items=argv["max_items"],
        apply=argv.get("apply", False),
        session_factory=lambda: session,
        service_factory=lambda created_session: active_service,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue(), session, active_service


def test_default_parser_is_dry_run() -> None:
    args = uae_classification_cli._build_parser().parse_args([])

    assert args.max_items == 20
    assert args.apply is False


def test_default_dry_run_output() -> None:
    code, stdout, stderr, session, service = run_cli({"max_items": 5})

    assert code == 0
    assert "Mode: dry-run" in stdout
    assert "Processed: 5" in stdout
    assert "Would update: 2" in stdout
    assert "Skipped protected: 1" in stdout
    assert stderr == ""
    assert session.closed == 1
    assert service.calls == [(5, False)]


def test_explicit_apply_output() -> None:
    code, stdout, stderr, _, service = run_cli({"max_items": 5, "apply": True})

    assert code == 0
    assert "Mode: apply" in stdout
    assert "Updated: 2" in stdout
    assert "Would update" not in stdout
    assert stderr == ""
    assert service.calls == [(5, True)]


@pytest.mark.parametrize("value", [0, -1, "twenty", 501])
def test_invalid_max_items_are_rejected(value) -> None:
    stdout = StringIO()
    stderr = StringIO()

    code = uae_classification_cli.run_classification(
        max_items=value,
        apply=False,
        session_factory=FakeSession,
        service_factory=FakeService,
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 2
    assert stdout.getvalue() == ""
    assert "Invalid UAE classification parameters." in stderr.getvalue()


def test_parser_rejects_malformed_values() -> None:
    with pytest.raises(uae_classification_cli.CliArgumentError):
        uae_classification_cli._build_parser().parse_args(["--max-items", "bad"])


def test_unrecoverable_service_error_returns_nonzero_without_trace() -> None:
    session = FakeSession()
    service = FakeService(session, fail=True)
    code, stdout, stderr, _, _ = run_cli({"max_items": 5}, service)

    assert code == 1
    assert stdout == ""
    assert "Manual UAE classification failed safely." in stderr
    assert "Traceback" not in stderr
    assert "private-password" not in stderr
