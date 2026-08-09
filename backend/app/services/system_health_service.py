"""Truthful bounded health probes for the protected operations dashboard."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.schemas.system import HealthComponentResponse, SystemHealthResponse
from app.core.config import Settings
from app.security.contracts import Permission
from app.services.operations_query_service import OperationsQueryError, OperationsQueryService


PREFECT_SERVER_HEALTH_URL = "http://prefect-server:4200/api/health"
PREFECT_WORKER_HEALTH_URL = "http://prefect-worker:8080/health"
MAX_HEALTH_RESPONSE_BYTES = 4096
PROBE_TIMEOUT = httpx.Timeout(3.0, connect=1.0, read=2.0, write=1.0, pool=1.0)


class SystemHealthService:
    def __init__(self, session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def snapshot(
        self,
        *,
        permissions: frozenset[Permission] = frozenset(),
    ) -> SystemHealthResponse:
        components = [
            self._component("backend", "healthy", "The API request path is available."),
            self._database(),
            self._http_probe("prefect_server", PREFECT_SERVER_HEALTH_URL),
            self._http_probe("prefect_worker", PREFECT_WORKER_HEALTH_URL),
        ]
        operations, freshness = self._operations(permissions)
        components.extend(
            [
                operations,
                freshness,
                self._storage(),
                self._deployment_identity(),
            ]
        )
        return SystemHealthResponse(
            status=self._overall(components),
            generated_at=datetime.now(UTC),
            version=self._settings.app_version,
            commit_sha=self._settings.app_commit_sha,
            components=components,
        )

    def _database(self) -> HealthComponentResponse:
        try:
            self._session.execute(select(1)).scalar_one()
        except SQLAlchemyError:
            return self._component(
                "database", "unhealthy", "The database probe failed safely."
            )
        return self._component("database", "healthy", "The database probe succeeded.")

    @staticmethod
    def _http_probe(name: str, url: str) -> HealthComponentResponse:
        try:
            with httpx.Client(
                timeout=PROBE_TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
            ) as client:
                with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > MAX_HEALTH_RESPONSE_BYTES:
                            return SystemHealthService._component(
                                name, "unhealthy", "The internal health response exceeded its bound."
                            )
                    if response.status_code != 200:
                        return SystemHealthService._component(
                            name, "unhealthy", "The internal health probe returned an unhealthy status."
                        )
        except (httpx.HTTPError, OSError):
            return SystemHealthService._component(
                name, "unhealthy", "The internal health probe was unavailable."
            )
        return SystemHealthService._component(
            name, "healthy", "The internal health probe succeeded."
        )

    def _operations(
        self,
        permissions: frozenset[Permission],
    ) -> tuple[HealthComponentResponse, HealthComponentResponse]:
        try:
            service = OperationsQueryService(self._session)
            summary = service.operations_summary()
            sources, total = service.list_sources(
                permissions=permissions, limit=100, offset=0
            )
        except (OperationsQueryError, ValueError):
            failed = self._component(
                "ingestion_operations", "unhealthy", "Operational evidence could not be loaded."
            )
            return failed, self._component(
                "source_freshness", "unknown", "Source freshness evidence is unavailable."
            )

        handler_count = int(summary["configured_handler_count"])
        operations_status = "disabled" if handler_count == 0 else "healthy"
        operations = self._component(
            "ingestion_operations",
            operations_status,
            (
                "Source execution handlers are intentionally inactive."
                if handler_count == 0
                else "Source execution handlers are available."
            ),
            configured_handlers=handler_count,
            active_cycles=int(summary["active_cycle_count"]),
            active_runs=int(summary["active_run_count"]),
            attention_count=int(summary["source_attention_count"]),
        )
        counts = {name: 0 for name in ("fresh", "stale", "never", "not_applicable")}
        disabled = 0
        for source in sources:
            freshness = str(source.get("freshness", "not_applicable"))
            if freshness in counts:
                counts[freshness] += 1
            if source.get("effective_state") in {"policy_disabled", "disabled", "paused"}:
                disabled += 1
        if handler_count == 0:
            freshness_status = "disabled"
            freshness_summary = "Collection is inactive; freshness is reported without fake success."
        elif counts["stale"] or counts["never"]:
            freshness_status = "stale"
            freshness_summary = "One or more enabled sources are stale or have never completed."
        else:
            freshness_status = "healthy"
            freshness_summary = "Enabled sources have current freshness evidence."
        return operations, self._component(
            "source_freshness",
            freshness_status,
            freshness_summary,
            total=min(total, 100),
            disabled=disabled,
            **counts,
        )

    def _storage(self) -> HealthComponentResponse:
        capacity = self._settings.storage_capacity_bytes
        if capacity is None:
            return self._component(
                "storage", "unknown", "No trustworthy storage capacity is configured."
            )
        try:
            used = int(
                self._session.execute(
                    select(func.pg_database_size(func.current_database()))
                ).scalar_one()
            )
        except (SQLAlchemyError, TypeError, ValueError):
            return self._component(
                "storage", "unknown", "Storage use could not be observed safely."
            )
        ratio = used / capacity
        state = "unhealthy" if ratio >= 0.95 else "degraded" if ratio >= 0.85 else "healthy"
        return self._component(
            "storage", state, "Configured database storage capacity was evaluated.",
            used_bytes=max(0, used), capacity_bytes=capacity, percent_used=round(ratio * 100, 2),
        )

    def _deployment_identity(self) -> HealthComponentResponse:
        if self._settings.app_commit_sha is None:
            return self._component(
                "deployment_identity", "unknown", "A deployed commit identity is not configured."
            )
        return self._component(
            "deployment_identity", "healthy", "Version and deployed commit identity are configured.",
            version=self._settings.app_version, commit_sha=self._settings.app_commit_sha,
        )

    @staticmethod
    def _overall(components: list[HealthComponentResponse]) -> str:
        states = {component.name: component.status for component in components}
        if states["database"] == "unhealthy":
            return "unhealthy"
        if any(state == "unhealthy" for state in states.values()):
            return "degraded"
        if any(state in {"degraded", "stale", "unknown"} for state in states.values()):
            return "degraded"
        return "healthy"

    @staticmethod
    def _component(name: str, status: str, summary: str, **observations) -> HealthComponentResponse:
        return HealthComponentResponse(
            name=name,
            status=status,
            summary=summary,
            observations=observations,
        )
