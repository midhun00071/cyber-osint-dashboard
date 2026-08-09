"""Fixed-vocabulary Prometheus metrics for private monitoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import Settings
from app.models import AuditEvent, IngestionCycle, IngestionRun
from app.services.system_health_service import SystemHealthService


METRIC_STATES = ("healthy", "degraded", "unhealthy", "stale", "disabled", "unknown")


class MetricsService:
    def __init__(self, session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def render(self) -> str:
        health = SystemHealthService(self._session, self._settings).snapshot()
        lines = [
            "# HELP alpha_data_component_health Fixed component health state.",
            "# TYPE alpha_data_component_health gauge",
        ]
        for component in health.components:
            for state in METRIC_STATES:
                value = 1 if component.status == state else 0
                lines.append(
                    f'alpha_data_component_health{{component="{component.name}",state="{state}"}} {value}'
                )
        freshness = next(item for item in health.components if item.name == "source_freshness")
        operations = next(item for item in health.components if item.name == "ingestion_operations")
        try:
            attention_count = max(0, int(operations.observations.get("attention_count", 0)))
        except (TypeError, ValueError):
            attention_count = 0
        lines.extend(
            [
                "# HELP alpha_data_source_freshness_count Bounded source freshness counts.",
                "# TYPE alpha_data_source_freshness_count gauge",
            ]
        )
        for state in ("fresh", "stale", "never", "not_applicable", "disabled"):
            value = freshness.observations.get(state, 0)
            lines.append(f'alpha_data_source_freshness_count{{state="{state}"}} {int(value)}')
        lines.extend(
            [
                "# HELP alpha_data_source_attention_count Sources requiring operator attention.",
                "# TYPE alpha_data_source_attention_count gauge",
                f"alpha_data_source_attention_count {attention_count}",
            ]
        )
        collection_success = 1
        try:
            active_cycles = int(
                self._session.execute(
                    select(func.count(IngestionCycle.id)).where(IngestionCycle.status == "running")
                ).scalar_one()
            )
            active_runs = int(
                self._session.execute(
                    select(func.count(IngestionRun.id)).where(
                        IngestionRun.status.in_(("running", "checkpoint_pending"))
                    )
                ).scalar_one()
            )
            since = datetime.now(UTC) - timedelta(minutes=15)
            auth_failures = int(
                self._session.execute(
                    select(func.count(AuditEvent.id)).where(
                        AuditEvent.occurred_at >= since,
                        AuditEvent.action.in_(("auth.login.failed", "authorization.denied")),
                    )
                ).scalar_one()
            )
        except (SQLAlchemyError, TypeError, ValueError):
            collection_success = 0
            active_cycles = active_runs = auth_failures = 0
        lines.extend(
            [
                "# HELP alpha_data_metrics_collection_success Whether database-backed metric collection succeeded.",
                "# TYPE alpha_data_metrics_collection_success gauge",
                f"alpha_data_metrics_collection_success {collection_success}",
                "# HELP alpha_data_ingestion_active_cycles Active ingestion cycles.",
                "# TYPE alpha_data_ingestion_active_cycles gauge",
                f"alpha_data_ingestion_active_cycles {active_cycles}",
                "# HELP alpha_data_ingestion_active_runs Active ingestion runs.",
                "# TYPE alpha_data_ingestion_active_runs gauge",
                f"alpha_data_ingestion_active_runs {active_runs}",
                "# HELP alpha_data_auth_abuse_events_recent Authentication failures and authorization denials in 15 minutes.",
                "# TYPE alpha_data_auth_abuse_events_recent gauge",
                f"alpha_data_auth_abuse_events_recent {auth_failures}",
                "# HELP alpha_data_backup_evidence_available Whether verified backup evidence is configured.",
                "# TYPE alpha_data_backup_evidence_available gauge",
                "alpha_data_backup_evidence_available 0",
            ]
        )
        storage = next(item for item in health.components if item.name == "storage")
        if "used_bytes" in storage.observations and "capacity_bytes" in storage.observations:
            lines.extend(
                [
                    "# HELP alpha_data_storage_bytes Database storage bytes when capacity is configured.",
                    "# TYPE alpha_data_storage_bytes gauge",
                    f'alpha_data_storage_bytes{{kind="used"}} {int(storage.observations["used_bytes"])}',
                    f'alpha_data_storage_bytes{{kind="capacity"}} {int(storage.observations["capacity_bytes"])}',
                ]
            )
        return "\n".join(lines) + "\n"
