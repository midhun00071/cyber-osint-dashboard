"""Centralized, allow-listed application logging configuration."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime


APPLICATION_LOGGER_NAME = "app"
APPLICATION_HANDLER_MARKER = "_cyber_osint_application_handler"
SUPPORTED_LOG_LEVELS = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:{}-]{1,240}$", flags=re.ASCII)
_ALLOWED_FIELDS = frozenset(
    {
        "event",
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
        "error_category",
        "operation_state",
    }
)


class UtcJsonFormatter(logging.Formatter):
    """Render fixed sanitized JSON without arbitrary LogRecord attributes."""

    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "level": record.levelname,
            "logger": record.name if record.name.startswith("app") else "app",
        }
        message = record.getMessage()
        for token in message.split():
            if "=" not in token:
                continue
            key, value = token.split("=", maxsplit=1)
            if key in _ALLOWED_FIELDS and _SAFE_VALUE.fullmatch(value):
                fields[key] = value
        if "event" not in fields:
            candidate = message.strip()
            fields["event"] = (
                candidate
                if _SAFE_VALUE.fullmatch(candidate) is not None
                else "application_event"
            )
        return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def normalize_log_level(value: str) -> str:
    """Return one supported log level without echoing rejected input."""

    normalized = value.strip().upper()
    if normalized not in SUPPORTED_LOG_LEVELS:
        raise ValueError(
            "LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL."
        )
    return normalized


def configure_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure exactly one handler for the application logger namespace."""

    normalized_level = normalize_log_level(log_level)
    level = logging.getLevelNamesMapping()[normalized_level]
    application_logger = logging.getLogger(APPLICATION_LOGGER_NAME)
    managed_handlers = [
        handler
        for handler in application_logger.handlers
        if getattr(handler, APPLICATION_HANDLER_MARKER, False)
    ]

    if managed_handlers:
        handler = managed_handlers[0]
        for duplicate in managed_handlers[1:]:
            application_logger.removeHandler(duplicate)
            duplicate.close()
    else:
        handler = logging.StreamHandler(sys.stdout)
        setattr(handler, APPLICATION_HANDLER_MARKER, True)
        application_logger.addHandler(handler)

    handler.setLevel(level)
    handler.setFormatter(
        UtcJsonFormatter()
    )
    application_logger.setLevel(level)
    application_logger.propagate = False

    # Uvicorn's request target can include raw query values. The application
    # emits one safer route-template completion event instead.
    logging.getLogger("uvicorn.access").disabled = True

    return application_logger
