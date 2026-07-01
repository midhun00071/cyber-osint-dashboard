import logging
import sys


def configure_logging(log_level: str = "INFO") -> None:
    """Configure application logging.

    Logs should support debugging without exposing secrets or sensitive values.
    """

    normalized_level = log_level.upper()
    level = getattr(logging, normalized_level, logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
