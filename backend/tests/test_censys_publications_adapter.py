from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path

import pytest

from app.ingestion.adapters import censys_publications
from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
    MAX_CENSYS_AUTHORS,
    MAX_CENSYS_CATEGORIES,
    MAX_CENSYS_FILE_BYTES,
    MAX_CENSYS_PUBLICATIONS,
    CensysPublicationFileError,
    CensysPublicationRecordError,
    adapt_censys_publication,
    derive_censys_external_id,
    load_censys_publication_file,
)


def valid_record(
    *,
    url: str = "https://censys.com/blog/example/",
) -> dict[str, object]:
    return {
        "title": " Example title ",
        "url": url,
        "summary": " Plain-text summary ",
        "published_at": "2026-06-01T12:00:00+04:00",
        "modified_at": None,
        "authors": [" Example Author "],
        "categories": [" Research "],
    }


def valid_document(
    *,
    source_slug: str = CENSYS_ARC_RESEARCH_SLUG,
    publications: list[object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_slug": source_slug,
        "publications": [valid_record()] if publications is None else publications,
    }


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def create_symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Symlink creation unavailable: {type(exc).__name__}")


def test_valid_file_and_record_normalize_to_safe_candidate(tmp_path: Path) -> None:
    document = load_censys_publication_file(
        write_json(tmp_path / "censys.json", valid_document())
    )
    candidate = adapt_censys_publication(
        document.source_slug,
        document.publications[0],
    )

    assert document.source_slug == CENSYS_ARC_RESEARCH_SLUG
    assert candidate.canonical_title == "Example title"
    assert candidate.canonical_url == "https://censys.com/blog/example/"
    assert candidate.summary == "Plain-text summary"
    assert candidate.source_published_at == datetime(2026, 6, 1, 8, 0, tzinfo=UTC)
    assert candidate.source_modified_at is None
    assert candidate.safe_source_payload == {
        "authors": ("Example Author",),
        "categories": ("Research",),
    }
    assert candidate.source_external_id.startswith("censys:arc-research:")


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "source_slug": CENSYS_ARC_RESEARCH_SLUG, "publications": []},
        {"schema_version": 1, "source_slug": CENSYS_ARC_RESEARCH_SLUG},
        {**valid_document(), "unexpected": True},
        {**valid_document(), "publications": {}},
        {**valid_document(), "source_slug": []},
        {**valid_document(), "source_slug": "google-threat-intelligence-public-research"},
        {**valid_document(), "source_slug": "arbitrary-source"},
    ],
)
def test_invalid_envelope_is_rejected(tmp_path: Path, payload: object) -> None:
    path = write_json(tmp_path / "invalid.json", payload)

    with pytest.raises(CensysPublicationFileError):
        load_censys_publication_file(path)


def test_malformed_json_and_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1,'
        '"source_slug":"censys-arc-research","publications":[]}',
        encoding="utf-8",
    )

    for path in (malformed, duplicate):
        with pytest.raises(CensysPublicationFileError):
            load_censys_publication_file(path)


def test_invalid_utf8_oversized_file_and_too_many_records_are_rejected(
    tmp_path: Path,
) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_CENSYS_FILE_BYTES + 1))
    too_many = write_json(
        tmp_path / "too-many.json",
        valid_document(publications=[{}] * (MAX_CENSYS_PUBLICATIONS + 1)),
    )

    for path in (invalid_utf8, oversized, too_many):
        with pytest.raises(CensysPublicationFileError):
            load_censys_publication_file(path)


def test_ordinary_relative_local_file_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_json(tmp_path / "relative.json", valid_document())
    monkeypatch.chdir(tmp_path)

    document = load_censys_publication_file(Path("relative.json"))

    assert document.source_slug == CENSYS_ARC_RESEARCH_SLUG


def test_ordinary_absolute_local_file_is_accepted(tmp_path: Path) -> None:
    path = write_json(tmp_path / "absolute.json", valid_document())

    assert path.is_absolute()
    document = load_censys_publication_file(path)

    assert document.source_slug == CENSYS_ARC_RESEARCH_SLUG


@pytest.mark.parametrize(
    "remote_path",
    [
        r"\\server\share\private-file.json",
        "//server/share/private-file.json",
        r"\\?\UNC\server\share\private-file.json",
        r"\\?\unc\server\share\private-file.json",
        r"\\.\device-or-path",
        r"\??\C:\private-file.json",
        r"\Device\HarddiskVolumeShadowCopy1\private-file.json",
    ],
)
def test_remote_and_device_paths_are_rejected_before_filesystem_traversal(
    remote_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_traversal(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Remote filesystem traversal must not be attempted.")

    monkeypatch.setattr(censys_publications.Path, "lstat", unexpected_traversal)
    monkeypatch.setattr(censys_publications.os, "open", unexpected_traversal)

    with pytest.raises(CensysPublicationFileError) as exc_info:
        load_censys_publication_file(remote_path)

    assert remote_path not in str(exc_info.value)


def test_direct_file_symlink_is_rejected(tmp_path: Path) -> None:
    target = write_json(tmp_path / "target.json", valid_document())
    symlink = tmp_path / "private-direct-link.json"
    create_symlink_or_skip(symlink, target, target_is_directory=False)

    with pytest.raises(CensysPublicationFileError) as exc_info:
        load_censys_publication_file(symlink)

    assert str(symlink) not in str(exc_info.value)


def test_parent_directory_symlink_is_rejected(tmp_path: Path) -> None:
    real_directory = tmp_path / "real-directory"
    real_directory.mkdir()
    write_json(real_directory / "data.json", valid_document())
    symlink = tmp_path / "private-parent-link"
    create_symlink_or_skip(symlink, real_directory, target_is_directory=True)

    supplied_path = symlink / "data.json"
    with pytest.raises(CensysPublicationFileError) as exc_info:
        load_censys_publication_file(supplied_path)

    assert str(supplied_path) not in str(exc_info.value)


def test_nested_parent_directory_symlink_is_rejected(tmp_path: Path) -> None:
    real_directory = tmp_path / "real-directory"
    nested_directory = real_directory / "nested"
    nested_directory.mkdir(parents=True)
    write_json(nested_directory / "data.json", valid_document())
    ordinary_parent = tmp_path / "ordinary-parent"
    ordinary_parent.mkdir()
    symlink = ordinary_parent / "private-nested-link"
    create_symlink_or_skip(symlink, real_directory, target_is_directory=True)

    supplied_path = symlink / "nested" / "data.json"
    with pytest.raises(CensysPublicationFileError) as exc_info:
        load_censys_publication_file(supplied_path)

    assert str(supplied_path) not in str(exc_info.value)


def test_opened_file_identity_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = write_json(tmp_path / "expected.json", valid_document())
    replacement = write_json(
        tmp_path / "replacement.json",
        valid_document(source_slug=CENSYS_RAPID_RESPONSE_SLUG, publications=[]),
    )
    real_open = os.open

    def open_replacement(path: object, flags: int) -> int:
        del path
        return real_open(replacement, flags)

    monkeypatch.setattr(censys_publications.os, "open", open_replacement)

    with pytest.raises(CensysPublicationFileError):
        load_censys_publication_file(expected)


def test_directory_http_path_and_deep_json_are_rejected(tmp_path: Path) -> None:
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 10 + "]" * 10, encoding="utf-8")

    paths: list[object] = [tmp_path, "https://censys.com/file.json", deep]
    for path in paths:
        with pytest.raises(CensysPublicationFileError) as exc_info:
            load_censys_publication_file(path)  # type: ignore[arg-type]
        assert str(path) not in str(exc_info.value)


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        {**valid_record(), "unexpected": True},
        {key: value for key, value in valid_record().items() if key != "title"},
        {**valid_record(), "authors": ["author"] * (MAX_CENSYS_AUTHORS + 1)},
        {**valid_record(), "categories": ["category"] * (MAX_CENSYS_CATEGORIES + 1)},
        {**valid_record(), "authors": [{"name": "nested"}]},
        {**valid_record(), "categories": [["nested"]]},
        {**valid_record(), "summary": "<p>raw HTML</p>"},
        {**valid_record(), "title": "<b>raw HTML</b>"},
        {**valid_record(), "title": "control\u0001"},
        {**valid_record(), "summary": "\ud800"},
        {**valid_record(), "published_at": "2026-06-01T12:00:00"},
    ],
)
def test_invalid_record_shapes_and_text_are_rejected(record: object) -> None:
    with pytest.raises(CensysPublicationRecordError):
        adapt_censys_publication(CENSYS_ARC_RESEARCH_SLUG, record)


@pytest.mark.parametrize("field", ["title", "summary", "authors", "categories"])
@pytest.mark.parametrize(
    "markup",
    [
        "<p>text</p>",
        "<!-- comment -->",
        "<!DOCTYPE html>",
        '<?xml version="1.0"?>',
        "<![CDATA[text]]>",
    ],
)
def test_raw_markup_is_rejected_from_all_plain_text_fields(
    field: str,
    markup: str,
) -> None:
    record = valid_record()
    record[field] = [markup] if field in {"authors", "categories"} else markup

    with pytest.raises(CensysPublicationRecordError) as exc_info:
        adapt_censys_publication(CENSYS_ARC_RESEARCH_SLUG, record)

    assert markup not in str(exc_info.value)


def test_comparison_prose_ampersands_and_normal_unicode_remain_allowed() -> None:
    record = valid_record()
    record.update(
        {
            "title": "TLS version < 1.3",
            "summary": "Risk score > 8",
            "authors": ["Research & Analysis"],
            "categories": ["\u0623\u0628\u062d\u0627\u062b \u0627\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a"],
        }
    )

    candidate = adapt_censys_publication(CENSYS_ARC_RESEARCH_SLUG, record)

    assert candidate.canonical_title == "TLS version < 1.3"
    assert candidate.summary == "Risk score > 8"
    assert candidate.safe_source_payload["authors"] == ("Research & Analysis",)


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/"),
        (
            CENSYS_RAPID_RESPONSE_SLUG,
            "https://censys.com/advisory/cve-example/",
        ),
    ],
)
def test_source_family_urls_are_accepted(source_slug: str, url: str) -> None:
    candidate = adapt_censys_publication(source_slug, valid_record(url=url))

    assert candidate.canonical_url == url


@pytest.mark.parametrize(
    ("source_slug", "url"),
    [
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/advisory/example/"),
        (CENSYS_RAPID_RESPONSE_SLUG, "https://censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://www.censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://docs.censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://platform.censys.io/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://app.censys.io/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://search.censys.io/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com.evil.example/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://evil-censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://@censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://user:secret@censys.com/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com:444/blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com.../blog/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/?token=secret"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/?signature=secret"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/?page=1"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/#fragment"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%2e%2e/advisory/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog%2Fexample/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/%62log/example/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%2Fadvisory/x/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%5Cadvisory/x/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%252e%252e/advisory/x/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%252Fadvisory/x/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/../advisory/x/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example\n"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%0Aencoded/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%FFinvalid/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%65xample/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%41RC/"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/%3Aexample/"),
        (
            CENSYS_RAPID_RESPONSE_SLUG,
            "https://censys.com/advisory/%63ve-example/",
        ),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example;param"),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/example/;param"),
        (
            CENSYS_RAPID_RESPONSE_SLUG,
            "https://censys.com/advisory/example;version=1",
        ),
        (CENSYS_ARC_RESEARCH_SLUG, "https://censys.com/blog/\ud800/"),
    ],
)
def test_unapproved_urls_are_rejected_without_disclosure(
    source_slug: str,
    url: str,
) -> None:
    with pytest.raises(CensysPublicationRecordError) as exc_info:
        adapt_censys_publication(source_slug, valid_record(url=url))

    message = str(exc_info.value)
    assert url not in message
    assert "secret" not in message


def test_tracking_only_query_is_removed_but_nontracking_query_is_rejected() -> None:
    candidate = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        valid_record(url="https://censys.com/blog/example/?utm_source=test&gclid=abc"),
    )

    assert candidate.canonical_url == "https://censys.com/blog/example/"


def test_percent_encoding_cannot_create_an_alternate_accepted_identity() -> None:
    literal = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        valid_record(url="https://censys.com/blog/example/"),
    )
    encoded_url = "https://censys.com/blog/%65xample/"

    with pytest.raises(CensysPublicationRecordError) as exc_info:
        adapt_censys_publication(
            CENSYS_ARC_RESEARCH_SLUG,
            valid_record(url=encoded_url),
        )

    assert encoded_url not in str(exc_info.value)
    assert literal.source_external_id == derive_censys_external_id(
        CENSYS_ARC_RESEARCH_SLUG,
        literal.canonical_url,
    )


def test_external_id_is_stable_canonical_and_source_separated() -> None:
    first = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        valid_record(url="HTTPS://CENSYS.COM:443/blog/example/?utm_source=test"),
    )
    second = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        valid_record(url="https://censys.com/blog/example/"),
    )
    advisory_id = derive_censys_external_id(
        CENSYS_RAPID_RESPONSE_SLUG,
        second.canonical_url,
    )

    assert first.source_external_id == second.source_external_id
    assert first.source_external_id != advisory_id
    assert len(first.source_external_id.rsplit(":", 1)[1]) == 64
