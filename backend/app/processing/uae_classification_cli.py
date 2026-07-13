"""Manual dry-run/apply CLI for UAE relevance classification."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import sys
from typing import TextIO

from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.processing.uae_classification_service import (
    MAX_CLASSIFICATION_ITEMS,
    UaeClassificationService,
    UaeClassificationServiceError,
)


DEFAULT_MAX_ITEMS = 20


class CliArgumentError(ValueError):
    """The manual classification command arguments were invalid."""


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliArgumentError("Invalid UAE classification arguments.")


def _bounded_integer(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer.") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}."
            )
        return parsed

    return parse


def _build_parser() -> CliArgumentParser:
    parser = CliArgumentParser(
        description="Manually classify stored records for direct UAE relevance.",
    )
    parser.add_argument(
        "--max-items",
        type=_bounded_integer("maximum items", 1, MAX_CLASSIFICATION_ITEMS),
        default=DEFAULT_MAX_ITEMS,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist eligible classification changes. Defaults to dry-run.",
    )
    return parser


def run_classification(
    *,
    max_items: int,
    apply: bool,
    session_factory: Callable[[], Session] = lambda: get_session_factory()(),
    service_factory: Callable[..., UaeClassificationService] = UaeClassificationService,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    if (
        not isinstance(max_items, int)
        or isinstance(max_items, bool)
        or not 1 <= max_items <= MAX_CLASSIFICATION_ITEMS
    ):
        print("Invalid UAE classification parameters.", file=stderr)
        return 2

    session: Session | None = None
    try:
        session = session_factory()
        service = service_factory(session)
        counts = service.classify_existing(max_items=max_items, apply=apply)
        print(f"Mode: {'apply' if apply else 'dry-run'}", file=stdout)
        print(f"Processed: {counts.processed}", file=stdout)
        if apply:
            print(f"Updated: {counts.updated}", file=stdout)
        else:
            print(f"Would update: {counts.would_update}", file=stdout)
        print(f"Unchanged: {counts.unchanged}", file=stdout)
        print(f"Skipped protected: {counts.skipped_protected}", file=stdout)
        print(f"Failed: {counts.failed}", file=stdout)
        return 0
    except (UaeClassificationServiceError, ValueError):
        print("Manual UAE classification failed safely.", file=stderr)
        return 1
    except Exception:
        print("Manual UAE classification failed unexpectedly.", file=stderr)
        return 1
    finally:
        if session is not None:
            session.close()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
    except CliArgumentError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return run_classification(max_items=arguments.max_items, apply=arguments.apply)


if __name__ == "__main__":
    raise SystemExit(main())
