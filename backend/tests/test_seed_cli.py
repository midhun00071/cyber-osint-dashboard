from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.dev_data import cli
from app.dev_data.seed_service import SeedCounts, SeedDatabaseError, SeedResult


@dataclass
class FakeSettings:
    app_env: str


class FakeSession:
    def __init__(self) -> None:
        self.closed = False
        self.rollbacks = 0

    def close(self) -> None:
        self.closed = True

    def rollback(self) -> None:
        self.rollbacks += 1


def configure_cli(
    monkeypatch: pytest.MonkeyPatch,
    *,
    app_env: str,
    result: SeedResult | Exception | None = None,
) -> FakeSession:
    fake_session = FakeSession()
    monkeypatch.setattr(cli, "get_settings", lambda: FakeSettings(app_env=app_env))
    monkeypatch.setattr(cli, "get_session_factory", lambda: lambda: fake_session)

    if result is None:
        result = SeedResult(
            created=SeedCounts(
                sources=4,
                tags=12,
                intelligence_items=10,
                identifiers=14,
                vulnerabilities=4,
                source_records=10,
                item_tag_associations=36,
            ),
            existing=SeedCounts(),
        )

    def fake_seed(session):
        assert session is fake_session
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(cli, "seed_development_data", fake_seed)
    return fake_session


@pytest.mark.parametrize("app_env", ["development", "test", " Development "])
def test_cli_allows_development_and_test_environments(
    monkeypatch,
    capsys,
    app_env,
):
    session = configure_cli(monkeypatch, app_env=app_env)

    exit_code = cli.main([])

    output = capsys.readouterr()
    assert exit_code == 0
    assert "Synthetic development seed data completed." in output.out
    assert "sources=4" in output.out
    assert "tags=12" in output.out
    assert "postgresql://" not in output.out
    assert session.closed is True


@pytest.mark.parametrize("app_env", ["production", "staging", ""])
def test_cli_rejects_production_like_or_missing_environment(
    monkeypatch,
    capsys,
    app_env,
):
    configure_cli(monkeypatch, app_env=app_env)

    exit_code = cli.main([])

    output = capsys.readouterr()
    assert exit_code == 2
    assert "APP_ENV must be development or test" in output.err
    assert "postgresql://" not in output.err


def test_cli_database_failure_returns_nonzero_without_secret_output(
    monkeypatch,
    capsys,
):
    session = configure_cli(
        monkeypatch,
        app_env="development",
        result=SeedDatabaseError("postgresql://user:secret@example/db"),
    )

    exit_code = cli.main([])

    output = capsys.readouterr()
    assert exit_code == 1
    assert "database operation did not complete" in output.err
    assert "postgresql://" not in output.err
    assert "secret" not in output.err.lower()
    assert session.rollbacks == 1
    assert session.closed is True
