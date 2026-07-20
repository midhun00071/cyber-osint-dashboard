"""Centralized, allow-listed application logging configuration."""

from __future__ import annotations

import logging
import sys
import time


APPLICATION_LOGGER_NAME = "app"
APPLICATION_HANDLER_MARKER = "_cyber_osint_application_handler"
SUPPORTED_LOG_LEVELS = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


class UtcKeyValueFormatter(logging.Formatter):
    """Render stable key-value records with UTC timestamps."""

    converter = time.gmtime


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
        UtcKeyValueFormatter(
            "timestamp=%(asctime)s level=%(levelname)s "
            "logger=%(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    application_logger.setLevel(level)
    application_logger.propagate = False

    # Uvicorn's request target can include raw query values. The application
    # emits one safer route-template completion event instead.
    logging.getLogger("uvicorn.access").disabled = True

    return application_logger
