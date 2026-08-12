from __future__ import annotations

from pathlib import Path
import re

import pytest

from app.ingestion.censys_publications_cli import _build_parser as build_local_parser
from app.ingestion.censys_publications_live_cli import (
    _build_parser as build_live_parser,
    main as live_main,
)
from app.ingestion.source_registry import AccessMethod, get_source_definition


PROJECT_ROOT = Path(__file__).resolve().parents[2]
README_PATH = PROJECT_ROOT / "README.md"
DATA_SOURCES_PATH = PROJECT_ROOT / "docs" / "data-sources.md"
ARCHITECTURE_PATH = PROJECT_ROOT / "docs" / "architecture.md"
SOURCE_ASSESSMENT_PATH = PROJECT_ROOT / "docs" / "source-assessment-matrix.md"


def normalized_document(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_data_source_guide_documents_supported_manual_live_commands_and_bounds() -> None:
    readme = normalized_document(DATA_SOURCES_PATH)
    plain_readme = readme.replace("`", "")

    assert "app.ingestion.censys_publications_live_cli" in readme
    assert "--source arc" in readme
    assert "--source rapid-response" in readme
    assert readme.count("--max-records 5") >= 2
    assert "--source is required" in plain_readme
    assert "defaults to 5" in plain_readme
    assert "valid range is 1 through 20" in plain_readme
    assert "manual-only" in plain_readme


def test_documented_censys_commands_match_supported_parser_options() -> None:
    arc = build_live_parser().parse_args(
        ["--source", "arc", "--max-records", "5"]
    )
    rapid_response = build_live_parser().parse_args(
        ["--source", "rapid-response", "--max-records", "5"]
    )
    local = build_local_parser().parse_args(
        ["--file", "reviewed-local-json-file"]
    )

    assert (arc.source, arc.max_records) == ("arc", 5)
    assert (rapid_response.source, rapid_response.max_records) == (
        "rapid-response",
        5,
    )
    assert local.file_path == "reviewed-local-json-file"


def test_data_source_guide_documents_local_fallback_and_security_boundaries() -> None:
    readme = normalized_document(DATA_SOURCES_PATH)

    assert "app.ingestion.censys_publications_cli" in readme
    assert "--file <reviewed-local-json-file>" in readme
    assert "reviewed local-file fallback" in readme
    assert "strict reviewed JSON fallback" in readme
    assert "no arbitrary URL input is available" in readme
    assert "Raw HTML and JSON-LD are not stored" in readme
    assert "There is no scheduler, startup hook, background worker" in readme
    assert "frontend invocation" in readme
    assert "must not be used to scan, probe, search, or rescan internet assets" in readme

    root_readme = normalized_document(README_PATH)
    assert "[Data sources](docs/data-sources.md)" in root_readme
    assert "app.ingestion.censys_publications_live_cli" not in root_readme


def test_censys_source_document_matches_live_and_fallback_architecture() -> None:
    source_document = normalized_document(DATA_SOURCES_PATH)

    assert "closed selectors `arc` and `rapid-response`" in source_document
    assert "no arbitrary URL input is available" in source_document
    assert "Raw HTML and JSON-LD are not stored" in source_document
    assert "reviewed local-file fallback remains supported" in source_document
    assert "There is no scheduler, startup hook, background worker" in source_document


def test_repository_architecture_documents_current_censys_integration() -> None:
    architecture = normalized_document(ARCHITECTURE_PATH)
    assessment = normalized_document(SOURCE_ASSESSMENT_PATH)

    assert "bounded live and reviewed local-file Censys" in architecture
    assert "fixed approved public discovery page in code" in architecture
    assert "stores no raw HTML or JSON-LD" in architecture
    assert "P9-04 reviewed local-file importer" in architecture
    assert "only implemented Censys behavior is the P9-04 offline" not in architecture
    assert "two Censys publication sources with bounded manual live" in assessment
    assert "Retained reviewed Censys local-file fallback" in assessment


def test_implemented_censys_assessment_rows_describe_non_rss_collection() -> None:
    lines = SOURCE_ASSESSMENT_PATH.read_text(encoding="utf-8").splitlines()
    header = next(line for line in lines if line.startswith("| Vendor |"))
    headings = [cell.strip() for cell in header.strip("|").split("|")]
    rows: dict[str, dict[str, str]] = {}

    for line in lines:
        if not line.startswith("| Censys |") or "`implement_now`" not in line:
            continue
        values = [cell.strip() for cell in line.strip("|").split("|")]
        row = dict(zip(headings, values, strict=True))
        rows[row["Source family"]] = row

    assert set(rows) == {"ARC research", "Rapid response advisories"}
    for row in rows.values():
        rss_status = row["RSS/feed availability"]
        ingestion_approach = row["Safe project ingestion approach"]

        assert "RSS is not used by this integration" in rss_status
        assert "fixed approved public discovery page" in rss_status
        assert "No RSS" not in rss_status
        assert "Implemented bounded manual live metadata collection" in ingestion_approach


def test_censys_registry_and_cli_configuration_add_no_rss_endpoint() -> None:
    arc = get_source_definition("censys-arc-research")
    rapid_response = get_source_definition("censys-rapid-response-advisories")

    assert {
        (source.access_method, source.source_type, source.base_url)
        for source in (arc, rapid_response)
    } == {
        (AccessMethod.MANUAL_CATALOGUE, "json", "https://censys.com/blog/"),
        (AccessMethod.MANUAL_CATALOGUE, "json", "https://censys.com/advisory/"),
    }

    live_options = {
        option
        for action in build_live_parser()._actions
        for option in action.option_strings
    }
    local_options = {
        option
        for action in build_local_parser()._actions
        for option in action.option_strings
    }
    assert live_options == {"-h", "--help", "--source", "--max-records"}
    assert local_options == {"-h", "--help", "--file"}


def test_readme_contains_no_developer_path_or_obvious_secret_assignment() -> None:
    readme = README_PATH.read_text(encoding="utf-8")

    assert re.search(r"(?i)[a-z]:\\users\\[^\\\s]+", readme) is None
    assert re.search(r"(?i)postgres(?:ql)?://\S*:\S*@", readme) is None
    assert (
        re.search(
            r"(?i)(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s<]+",
            readme,
        )
        is None
    )


def test_live_help_exits_before_collector_or_database_creation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = {"collector": 0, "session": 0}

    def collector_factory() -> object:
        calls["collector"] += 1
        raise AssertionError("collector must not be created for help")

    def session_factory() -> object:
        calls["session"] += 1
        raise AssertionError("session must not be created for help")

    with pytest.raises(SystemExit) as exc_info:
        live_main(
            ["--help"],
            collector_factory=collector_factory,  # type: ignore[arg-type]
            session_factory=session_factory,  # type: ignore[arg-type]
        )

    output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "--source" in output.out
    assert "--max-records" in output.out
    assert output.err == ""
    assert calls == {"collector": 0, "session": 0}
