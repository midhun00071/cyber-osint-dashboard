"""Persistence services for normalized defensive intelligence."""

from app.ingestion.services.nvd_ingestion_service import (
    NvdIngestionService,
    NvdPersistenceError,
    NvdPersistenceResult,
)
from app.ingestion.services.operational_persistence_service import (
    DeferReason,
    OperationalConflictError,
    OperationalLockUnavailableError,
    OperationalMissingRecordError,
    OperationalPersistenceError,
    OperationalPersistenceFailure,
    OperationalPersistenceService,
    OperationalStaleStateError,
    OperationalValidationError,
    RunCounters,
)


__all__ = [
    "NvdIngestionService",
    "NvdPersistenceError",
    "NvdPersistenceResult",
    "DeferReason",
    "OperationalConflictError",
    "OperationalLockUnavailableError",
    "OperationalMissingRecordError",
    "OperationalPersistenceError",
    "OperationalPersistenceFailure",
    "OperationalPersistenceService",
    "OperationalStaleStateError",
    "OperationalValidationError",
    "RunCounters",
]
