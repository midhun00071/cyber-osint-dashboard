"""Manual CLI for inserting synthetic development cybersecurity data."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.dev_data.seed_service import (
    SeedConflictError,
    SeedDatabaseError,
    SeedResult,
    seed_development_data,
)


ALLOWED_APP_ENVS = {"development", "test"}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the seed command and return a process exit code."""

    del argv
    settings = get_settings()
    app_env = settings.app_env.strip().lower()

    if app_env not in ALLOWED_APP_ENVS:
        print(
            "Refusing to seed synthetic development data because APP_ENV must be "
            "development or test.",
            file=sys.stderr,
        )
        return 2

    session = get_session_factory()()
    try:
        result = seed_development_data(session)
    except SeedConflictError as exc:
        session.rollback()
        print(f"Seed data conflict: {exc}", file=sys.stderr)
        return 3
    except (SeedDatabaseError, SQLAlchemyError):
        session.rollback()
        print(
            "Seed data failed because the database operation did not complete.",
            file=sys.stderr,
        )
        return 1
    finally:
        session.close()

    print(_format_result(result))
    return 0


def _format_result(result: SeedResult) -> str:
    created = result.created
    existing = result.existing
    return "\n".join(
        [
            "Synthetic development seed data completed.",
            (
                "created: "
                f"sources={created.sources}, tags={created.tags}, "
                f"intelligence_items={created.intelligence_items}, "
                f"identifiers={created.identifiers}, "
                f"vulnerabilities={created.vulnerabilities}, "
                f"source_records={created.source_records}, "
                f"item_tag_associations={created.item_tag_associations}"
            ),
            (
                "existing: "
                f"sources={existing.sources}, tags={existing.tags}, "
                f"intelligence_items={existing.intelligence_items}, "
                f"identifiers={existing.identifiers}, "
                f"vulnerabilities={existing.vulnerabilities}, "
                f"source_records={existing.source_records}, "
                f"item_tag_associations={existing.item_tag_associations}"
            ),
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
