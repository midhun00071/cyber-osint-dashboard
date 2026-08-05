"""Atomic, audited source controls and durable operation acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ingestion.services.operational_idempotency import build_manual_cycle_key
from app.ingestion.services.operational_persistence_service import (
    OperationalConflictError,
    OperationalPersistenceError,
    OperationalPersistenceService,
)
from app.ingestion.source_registry import ImplementationStatus, get_source_definition
from app.models import (
    IngestionCycle,
    IngestionError,
    IngestionRun,
    IntelligenceSource,
    SourceCredentialReference,
    SourceRateLimitState,
)
from app.orchestration.flows import DEFAULT_SOURCE_HANDLERS
from app.security.contracts import AuthenticatedPrincipal
from app.services.security_audit_service import SecurityAuditAction, SecurityAuditService


ACTIVE_RUN_STATUSES = frozenset({"running", "checkpoint_pending"})
MAX_POLICY_ATTEMPTS = 3


class OperatorControlError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        action: SecurityAuditAction,
        target_type: str,
        target_ref: str,
        reason: str,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.status_code = status_code
        self.action = action
        self.target_type = target_type
        self.target_ref = target_ref
        self.reason = reason


@dataclass(frozen=True, slots=True)
class OperationAcceptance:
    cycle_public_id: UUID
    run_public_id: UUID
    source_slug: str
    trigger_type: str
    status: str
    accepted_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class SourceTransition:
    source_public_id: UUID
    source_slug: str
    prior_state: str
    operator_state: str
    changed: bool


class OperatorControlService:
    def __init__(
        self,
        session: Session,
        *,
        execution_slugs: Iterable[str] | None = None,
    ) -> None:
        self._session = session
        self._execution_slugs = frozenset(
            DEFAULT_SOURCE_HANDLERS if execution_slugs is None else execution_slugs
        )
        self._audit = SecurityAuditService(session)

    def request_manual_run(
        self,
        *,
        source_slug: str,
        idempotency_key: str,
        actor: AuthenticatedPrincipal,
        correlation_id: str | UUID,
        occurred_at: datetime | None = None,
    ) -> OperationAcceptance:
        now = _utc(occurred_at)
        action = SecurityAuditAction.INGESTION_MANUAL_REQUESTED
        source = self._locked_source(source_slug, action)
        self._require_runtime_eligible(source, action)
        cycle_key = build_manual_cycle_key(idempotency_key)
        existing_cycle = self._session.scalar(
            select(IngestionCycle).where(IngestionCycle.idempotency_key == cycle_key)
        )
        replayed = existing_cycle is not None
        if existing_cycle is not None:
            existing_run = self._session.execute(
                select(IngestionRun, IntelligenceSource.slug)
                .join(IntelligenceSource, IntelligenceSource.id == IngestionRun.source_id)
                .where(IngestionRun.cycle_id == existing_cycle.id)
                .order_by(IngestionRun.attempt_number, IngestionRun.id)
            ).first()
            if existing_run is not None and existing_run[1] != source.slug:
                self._raise(
                    "idempotency_conflict", "The operation conflicts with existing evidence.",
                    409, action, "intelligence_source", source.slug, "idempotency_conflict",
                )
        try:
            persistence = OperationalPersistenceService(self._session)
            cycle = persistence.acquire_cycle(
                trigger_type="manual",
                manual_request_key=idempotency_key,
                sources_expected=1,
                actor_type="user",
                actor_ref=str(actor.user_public_id),
                occurred_at=now,
                safe_summary="Manual source run accepted for durable execution.",
            )
            run = persistence.acquire_source_run(
                cycle_id=cycle.id,
                source_slug=source.slug,
                occurred_at=now,
            )
        except OperationalConflictError:
            self._raise(
                "source_active", "The source already has an active operation.",
                409, action, "intelligence_source", source.slug, "source_active",
            )
        except OperationalPersistenceError:
            raise OperatorControlError(
                "operation_unavailable", "The operation could not be accepted safely.",
                status_code=500, action=action, target_type="intelligence_source",
                target_ref=source.slug, reason="persistence_failed",
            ) from None
        self._audit.append(
            action=action,
            actor_type="user",
            actor_ref=str(actor.user_public_id),
            target_type="ingestion_run",
            target_ref=str(run.public_id),
            outcome="no_change" if replayed else "success",
            correlation_id=correlation_id,
            safe_detail={"reason": "idempotent_replay"} if replayed else {"trigger_type": "manual"},
            occurred_at=now,
        )
        return OperationAcceptance(
            cycle_public_id=cycle.public_id,
            run_public_id=run.public_id,
            source_slug=source.slug,
            trigger_type="manual",
            status=run.status,
            accepted_at=run.created_at,
            replayed=replayed,
        )

    def request_retry(
        self,
        *,
        run_public_id: UUID,
        actor: AuthenticatedPrincipal,
        correlation_id: str | UUID,
        occurred_at: datetime | None = None,
    ) -> OperationAcceptance:
        now = _utc(occurred_at)
        action = SecurityAuditAction.INGESTION_RETRY_REQUESTED
        row = self._session.execute(
            select(IngestionRun, IntelligenceSource)
            .join(IntelligenceSource, IntelligenceSource.id == IngestionRun.source_id)
            .where(IngestionRun.public_id == run_public_id)
            .with_for_update()
        ).one_or_none()
        if row is None:
            self._raise(
                "run_not_found", "The requested run was not found.", 404, action,
                "ingestion_run", str(run_public_id), "not_found",
            )
        prior, source = row
        self._require_runtime_eligible(source, action)
        existing = self._session.scalars(
            select(IngestionRun)
            .where(IngestionRun.retry_of_run_id == prior.id)
            .order_by(IngestionRun.attempt_number, IngestionRun.id)
            .with_for_update()
        ).first()
        if existing is not None:
            cycle = self._session.get(IngestionCycle, existing.cycle_id)
            if cycle is None:
                raise OperatorControlError(
                    "operation_unavailable", "The operation could not be accepted safely.",
                    status_code=500, action=action, target_type="ingestion_run",
                    target_ref=str(run_public_id), reason="evidence_unavailable",
                )
            self._append_acceptance_audit(action, actor, existing, correlation_id, now, replayed=True)
            return _acceptance(cycle, source, existing, replayed=True)
        if prior.status not in {"failed", "partial"}:
            self._raise(
                "retry_not_allowed", "The run is not eligible for retry.", 409,
                action, "ingestion_run", str(run_public_id), "status_not_retryable",
            )
        if prior.attempt_number is None or prior.attempt_number + 1 >= MAX_POLICY_ATTEMPTS:
            self._raise(
                "retry_exhausted", "The retry attempt limit has been reached.", 409,
                action, "ingestion_run", str(run_public_id), "retry_exhausted",
            )
        retryable = self._session.scalar(
            select(IngestionError.id).where(
                IngestionError.ingestion_run_id == prior.id,
                IngestionError.retryable.is_(True),
            ).limit(1)
        )
        if retryable is None:
            self._raise(
                "retry_not_allowed", "The run has no retryable failure evidence.", 409,
                action, "ingestion_run", str(run_public_id), "failure_not_retryable",
            )
        try:
            retry = OperationalPersistenceService(self._session).acquire_retry(
                prior_run_id=prior.id, occurred_at=now
            )
        except OperationalConflictError:
            self._raise(
                "retry_conflict", "The retry parent is stale or already branched.", 409,
                action, "ingestion_run", str(run_public_id), "retry_conflict",
            )
        except OperationalPersistenceError:
            raise OperatorControlError(
                "operation_unavailable", "The operation could not be accepted safely.",
                status_code=500, action=action, target_type="ingestion_run",
                target_ref=str(run_public_id), reason="persistence_failed",
            ) from None
        cycle = self._session.get(IngestionCycle, retry.cycle_id)
        if cycle is None:
            raise OperatorControlError(
                "operation_unavailable", "The operation could not be accepted safely.",
                status_code=500, action=action, target_type="ingestion_run",
                target_ref=str(run_public_id), reason="evidence_unavailable",
            )
        self._append_acceptance_audit(action, actor, retry, correlation_id, now, replayed=False)
        return _acceptance(cycle, source, retry, replayed=False)

    def transition_source(
        self,
        *,
        source_slug: str,
        operation: str,
        actor: AuthenticatedPrincipal,
        correlation_id: str | UUID,
        occurred_at: datetime | None = None,
    ) -> SourceTransition:
        actions = {
            "pause": SecurityAuditAction.SOURCE_PAUSED,
            "resume": SecurityAuditAction.SOURCE_RESUMED,
            "disable": SecurityAuditAction.SOURCE_DISABLED,
            "enable": SecurityAuditAction.SOURCE_ENABLED,
        }
        if operation not in actions:
            raise ValueError("Unsupported source transition.")
        action = actions[operation]
        now = _utc(occurred_at)
        source = self._locked_source(source_slug, action)
        definition = get_source_definition(source.slug)
        target = {"pause": "paused", "resume": "enabled", "disable": "disabled", "enable": "enabled"}[operation]
        prior = source.operator_state
        if bool(self._session.scalar(
            select(IngestionRun.id).where(
                IngestionRun.source_id == source.id,
                IngestionRun.status.in_(ACTIVE_RUN_STATUSES),
            ).limit(1)
        )):
            self._raise(
                "source_active", "The source has an active operation.", 409,
                action, "intelligence_source", source.slug, "source_active",
            )
        if prior == target:
            self._append_transition_audit(action, actor, source, prior, target, correlation_id, now, changed=False)
            return SourceTransition(source.public_id, source.slug, prior, target, False)
        if operation in {"resume", "enable"} and (
            definition.implementation_status is not ImplementationStatus.IMPLEMENTED
            or not definition.enabled
        ):
            self._raise(
                "source_not_eligible", "The source is disabled by immutable policy.", 409,
                action, "intelligence_source", source.slug, "policy_disabled",
            )
        allowed = {
            ("enabled", "pause"), ("paused", "resume"),
            ("enabled", "disable"), ("paused", "disable"),
            ("disabled", "enable"),
        }
        if (prior, operation) not in allowed:
            self._raise(
                "invalid_transition", "The source transition is not allowed.", 409,
                action, "intelligence_source", source.slug, "invalid_transition",
            )
        source.operator_state = target
        source.is_enabled = target == "enabled"
        source.updated_at = now
        self._session.flush()
        self._append_transition_audit(action, actor, source, prior, target, correlation_id, now, changed=True)
        return SourceTransition(source.public_id, source.slug, prior, target, True)

    def audit_denial(
        self,
        error: OperatorControlError,
        *,
        actor: AuthenticatedPrincipal,
        correlation_id: str | UUID,
    ) -> None:
        self._audit.append(
            action=error.action,
            actor_type="user",
            actor_ref=str(actor.user_public_id),
            target_type=error.target_type,
            target_ref=error.target_ref,
            outcome="denied" if error.status_code < 500 else "failed",
            correlation_id=correlation_id,
            safe_detail={"reason": error.reason},
        )

    def _locked_source(self, slug: str, action: SecurityAuditAction) -> IntelligenceSource:
        try:
            get_source_definition(slug)
        except Exception:
            self._raise(
                "source_not_found", "The requested source was not found.", 404,
                action, "intelligence_source", slug, "not_found",
            )
        source = self._session.scalar(
            select(IntelligenceSource).where(IntelligenceSource.slug == slug).with_for_update()
        )
        if source is None:
            self._raise(
                "source_not_found", "The requested source was not found.", 404,
                action, "intelligence_source", slug, "not_found",
            )
        return source

    def _require_runtime_eligible(self, source: IntelligenceSource, action: SecurityAuditAction) -> None:
        definition = get_source_definition(source.slug)
        if definition.implementation_status is not ImplementationStatus.IMPLEMENTED or not definition.enabled:
            self._raise(
                "source_not_eligible", "The source is disabled by immutable policy.", 409,
                action, "intelligence_source", source.slug, "policy_disabled",
            )
        if source.operator_state != "enabled" or not source.is_enabled:
            self._raise(
                "source_not_eligible", "The source is not enabled for operations.", 409,
                action, "intelligence_source", source.slug, "operator_disabled",
            )
        if definition.authentication_required and not bool(self._session.scalar(
            select(SourceCredentialReference.id).where(
                SourceCredentialReference.source_id == source.id,
                SourceCredentialReference.configuration_state.in_({"configured", "rotation_due"}),
                SourceCredentialReference.external_reference_id.is_not(None),
            ).limit(1)
        )):
            self._raise(
                "credentials_required", "The source requires configured credentials.", 409,
                action, "intelligence_source", source.slug, "credentials_required",
            )
        rate = self._session.scalars(
            select(SourceRateLimitState).where(SourceRateLimitState.source_id == source.id)
            .order_by(SourceRateLimitState.updated_at.desc(), SourceRateLimitState.id.desc()).limit(1)
        ).first()
        if rate is not None and rate.state == "quota_unavailable":
            self._raise(
                "quota_unavailable", "The source quota is unavailable.", 409,
                action, "intelligence_source", source.slug, "quota_unavailable",
            )
        if rate is not None and rate.state in {"limited", "backoff"} and (
            rate.backoff_until is None or _utc(rate.backoff_until) > datetime.now(UTC)
        ):
            self._raise(
                "rate_limited", "The source is rate limited.", 429,
                action, "intelligence_source", source.slug, "rate_limited",
            )
        if source.slug not in self._execution_slugs:
            self._raise(
                "execution_unavailable", "No approved execution binding is configured.", 409,
                action, "intelligence_source", source.slug, "execution_unavailable",
            )

    def _append_acceptance_audit(self, action, actor, run, correlation_id, now, *, replayed):
        self._audit.append(
            action=action, actor_type="user", actor_ref=str(actor.user_public_id),
            target_type="ingestion_run", target_ref=str(run.public_id),
            outcome="no_change" if replayed else "success", correlation_id=correlation_id,
            safe_detail={"reason": "idempotent_replay"} if replayed else {"trigger_type": "retry"},
            occurred_at=now,
        )

    def _append_transition_audit(self, action, actor, source, prior, target, correlation_id, now, *, changed):
        self._audit.append(
            action=action, actor_type="user", actor_ref=str(actor.user_public_id),
            target_type="intelligence_source", target_ref=source.slug,
            outcome="success" if changed else "no_change", correlation_id=correlation_id,
            safe_detail={"prior_state": prior, "new_state": target}, occurred_at=now,
        )

    @staticmethod
    def _raise(code, message, status_code, action, target_type, target_ref, reason):
        raise OperatorControlError(
            code, message, status_code=status_code, action=action,
            target_type=target_type, target_ref=target_ref, reason=reason,
        )


def _acceptance(cycle, source, run, *, replayed: bool) -> OperationAcceptance:
    return OperationAcceptance(
        cycle_public_id=cycle.public_id, run_public_id=run.public_id,
        source_slug=source.slug, trigger_type="retry", status=run.status,
        accepted_at=run.created_at, replayed=replayed,
    )


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware timestamp is required.")
    return value.astimezone(UTC)


__all__ = [
    "MAX_POLICY_ATTEMPTS", "OperationAcceptance", "OperatorControlError",
    "OperatorControlService", "SourceTransition",
]
