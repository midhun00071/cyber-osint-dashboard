from __future__ import annotations

from datetime import UTC, datetime
from html import escape
import json
import os
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from app.ingestion.adapters import anomali_publications
from app.ingestion.adapters.anomali_publications import (
    ANOMALI_SOURCE_SLUG,
    MAX_ANOMALI_AUTHORS,
    MAX_ANOMALI_CATEGORIES,
    MAX_ANOMALI_ENTITY_DECODE_PASSES,
    MAX_ANOMALI_FILE_BYTES,
    MAX_ANOMALI_PUBLICATIONS,
    AnomaliPublicationFileError,
    AnomaliPublicationRecordError,
    adapt_anomali_publication,
    derive_anomali_external_id,
    load_anomali_publication_file,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    normalize_publication_candidate,
)


def valid_record(
    *,
    title: str = "Anomali Cyber Watch: Example publication",
    url: str = "https://www.anomali.com/blog/anomali-cyber-watch-example-publication",
) -> dict[str, object]:
    return {
        "title": title,
        "url": url,
        "summary": "Operator-prepared plain-text summary.",
        "published_at": "2026-01-27T00:00:00Z",
        "modified_at": None,
        "authors": ["Anomali Cyber Watch"],
        "categories": ["Anomali Cyber Watch"],
    }


def valid_document(publications: list[object] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_slug": ANOMALI_SOURCE_SLUG,
        "publications": [valid_record()] if publications is None else publications,
    }


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def encode_entities(value: str, levels: int) -> str:
    for _ in range(levels):
        value = escape(value)
    return value


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


def test_valid_file_and_record_produce_immutable_safe_candidate(tmp_path: Path) -> None:
    document = load_anomali_publication_file(
        write_json(tmp_path / "anomali.json", valid_document())
    )
    record = document.publications[0]
    candidate = adapt_anomali_publication(record)

    assert document.source_slug == ANOMALI_SOURCE_SLUG
    assert isinstance(document.publications, tuple)
    assert isinstance(record, MappingProxyType)
    assert record["authors"] == ("Anomali Cyber Watch",)  # type: ignore[index]
    with pytest.raises(TypeError):
        record["title"] = "changed"  # type: ignore[index]
    assert candidate.canonical_title == "Anomali Cyber Watch: Example publication"
    assert candidate.canonical_url == (
        "https://www.anomali.com/blog/anomali-cyber-watch-example-publication"
    )
    assert candidate.summary == "Operator-prepared plain-text summary."
    assert candidate.source_published_at == datetime(2026, 1, 27, tzinfo=UTC)
    assert candidate.source_modified_at is None
    assert candidate.safe_source_payload == {
        "authors": ("Anomali Cyber Watch",),
        "categories": ("Anomali Cyber Watch",),
    }
    assert normalize_publication_candidate(candidate).item_type == "threat_report"


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "source_slug": ANOMALI_SOURCE_SLUG, "publications": []},
        {"schema_version": True, "source_slug": ANOMALI_SOURCE_SLUG, "publications": []},
        {"schema_version": 1, "source_slug": ANOMALI_SOURCE_SLUG},
        {**valid_document(), "extra": None},
        {**valid_document(), "source_slug": "anomali-public-research"},
        {**valid_document(), "publications": {}},
    ],
)
def test_invalid_document_envelopes_are_rejected(tmp_path: Path, payload: object) -> None:
    with pytest.raises(AnomaliPublicationFileError):
        load_anomali_publication_file(write_json(tmp_path / "invalid.json", payload))


def test_empty_and_maximum_catalogues_are_accepted(tmp_path: Path) -> None:
    empty = load_anomali_publication_file(
        write_json(tmp_path / "empty.json", valid_document([]))
    )
    maximum = load_anomali_publication_file(
        write_json(
            tmp_path / "maximum.json",
            valid_document([{}] * MAX_ANOMALI_PUBLICATIONS),
        )
    )

    assert empty.publications == ()
    assert len(maximum.publications) == MAX_ANOMALI_PUBLICATIONS


def test_malformed_duplicate_keys_constants_and_depth_are_rejected(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    duplicate_root = tmp_path / "duplicate-root.json"
    duplicate_root.write_text(
        '{"schema_version":1,"schema_version":1,'
        '"source_slug":"anomali-cyber-watch","publications":[]}',
        encoding="utf-8",
    )
    duplicate_record = tmp_path / "duplicate-record.json"
    duplicate_record.write_text(
        '{"schema_version":1,"source_slug":"anomali-cyber-watch",'
        '"publications":[{"title":"one","title":"two"}]}',
        encoding="utf-8",
    )
    nan = tmp_path / "nan.json"
    nan.write_text(
        '{"schema_version":1,"source_slug":"anomali-cyber-watch",'
        '"publications":[NaN]}',
        encoding="utf-8",
    )
    infinity = tmp_path / "infinity.json"
    infinity.write_text(
        '{"schema_version":1,"source_slug":"anomali-cyber-watch",'
        '"publications":[Infinity]}',
        encoding="utf-8",
    )
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 10 + "]" * 10, encoding="utf-8")

    for path in (malformed, duplicate_root, duplicate_record, nan, infinity, deep):
        with pytest.raises(AnomaliPublicationFileError):
            load_anomali_publication_file(path)


def test_invalid_utf8_bom_oversize_and_record_limit_are_rejected(tmp_path: Path) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(valid_document()).encode())
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_ANOMALI_FILE_BYTES + 1))
    too_many = write_json(
        tmp_path / "too-many.json",
        valid_document([{}] * (MAX_ANOMALI_PUBLICATIONS + 1)),
    )

    for path in (invalid_utf8, bom, oversized, too_many):
        with pytest.raises(AnomaliPublicationFileError):
            load_anomali_publication_file(path)


def test_relative_and_absolute_regular_files_are_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = write_json(tmp_path / "relative.json", valid_document([]))
    assert load_anomali_publication_file(relative).publications == ()
    monkeypatch.chdir(tmp_path)
    assert load_anomali_publication_file(Path("relative.json")).publications == ()


@pytest.mark.parametrize(
    "remote_path",
    [
        r"\\server\share\catalogue.json",
        "//server/share/catalogue.json",
        r"\\?\UNC\server\share\catalogue.json",
        r"\\.\pipe\anomali-catalogue",
        r"\??\C:\catalogue.json",
        r"\Device\HarddiskVolumeShadowCopy1\catalogue.json",
    ],
)
def test_remote_device_and_pipe_paths_are_rejected_before_traversal(
    remote_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Filesystem traversal must not occur.")

    monkeypatch.setattr(anomali_publications.Path, "lstat", unexpected)
    monkeypatch.setattr(anomali_publications.os, "open", unexpected)

    with pytest.raises(AnomaliPublicationFileError) as exc_info:
        load_anomali_publication_file(remote_path)

    assert remote_path not in str(exc_info.value)


def test_file_and_parent_symlinks_are_rejected(tmp_path: Path) -> None:
    target = write_json(tmp_path / "target.json", valid_document([]))
    direct = tmp_path / "direct-link.json"
    create_symlink_or_skip(direct, target, target_is_directory=False)
    with pytest.raises(AnomaliPublicationFileError):
        load_anomali_publication_file(direct)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    write_json(real_parent / "data.json", valid_document([]))
    parent_link = tmp_path / "parent-link"
    create_symlink_or_skip(parent_link, real_parent, target_is_directory=True)
    with pytest.raises(AnomaliPublicationFileError):
        load_anomali_publication_file(parent_link / "data.json")


def test_missing_directory_and_http_paths_are_rejected(tmp_path: Path) -> None:
    for path in (tmp_path / "missing.json", tmp_path, "https://www.anomali.com/file"):
        with pytest.raises(AnomaliPublicationFileError) as exc_info:
            load_anomali_publication_file(path)  # type: ignore[arg-type]
        assert str(path) not in str(exc_info.value)


def test_descriptor_identity_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = write_json(tmp_path / "expected.json", valid_document([]))
    replacement = write_json(tmp_path / "replacement.json", valid_document([{}]))
    real_open = os.open

    def open_replacement(path: object, flags: int) -> int:
        del path
        return real_open(replacement, flags)

    monkeypatch.setattr(anomali_publications.os, "open", open_replacement)
    with pytest.raises(AnomaliPublicationFileError):
        load_anomali_publication_file(expected)


def test_file_growth_and_descriptor_closure_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_json(tmp_path / "growing.json", valid_document([]))
    real_fstat = os.fstat
    real_fdopen = os.fdopen
    calls = 0
    streams: list[object] = []

    def growing_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls == 1:
            return metadata
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=MAX_ANOMALI_FILE_BYTES + 1,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns,
            st_ino=metadata.st_ino,
            st_dev=metadata.st_dev,
        )

    def tracking_fdopen(descriptor: int, mode: str):
        stream = real_fdopen(descriptor, mode)
        streams.append(stream)
        return stream

    monkeypatch.setattr(anomali_publications.os, "fstat", growing_fstat)
    monkeypatch.setattr(anomali_publications.os, "fdopen", tracking_fdopen)

    with pytest.raises(AnomaliPublicationFileError):
        load_anomali_publication_file(path)

    assert streams and all(stream.closed for stream in streams)


def test_raw_descriptor_close_failure_is_source_specific_and_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_json(tmp_path / "close-failure.json", valid_document([]))
    real_close = os.close
    close_calls = 0

    def fail_fstat(descriptor: int):
        del descriptor
        raise OSError("private descriptor inspection detail")

    def close_then_fail(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        real_close(descriptor)
        raise OSError("private descriptor close detail")

    monkeypatch.setattr(anomali_publications.os, "fstat", fail_fstat)
    monkeypatch.setattr(anomali_publications.os, "close", close_then_fail)

    with pytest.raises(AnomaliPublicationFileError) as exc_info:
        load_anomali_publication_file(path)

    assert close_calls == 1
    assert str(exc_info.value) == (
        "The Anomali publication file could not be read safely."
    )
    assert "private" not in str(exc_info.value)


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        {**valid_record(), "content": "article body"},
        {**valid_record(), "iocs": ["192.0.2.1"]},
        {**valid_record(), "attachments": ["report.pdf"]},
        {key: value for key, value in valid_record().items() if key != "summary"},
        {**valid_record(), "title": 1},
        {**valid_record(), "summary": []},
        {**valid_record(), "authors": "Anomali"},
        {**valid_record(), "categories": {}},
    ],
)
def test_exact_record_schema_and_types_are_enforced(record: object) -> None:
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


@pytest.mark.parametrize(
    "title",
    [
        "Anomali Cyber Watch:",
        "Anomali Cyber Watch:   ",
        "Anomali cyber watch: Example",
        "General Anomali research",
        "Anomali Cyber Watch: <b>Example</b>",
        "Anomali Cyber Watch: &lt;script&gt;secret&lt;/script&gt;",
        "Anomali Cyber Watch: < script",
        "Anomali Cyber Watch: onload=secret",
        "Anomali Cyber Watch: bad\x01text",
        "Anomali Cyber Watch: \ud800",
        "Anomali Cyber Watch: bad\ufffdtext",
        "Anomali Cyber Watch: " + ("x" * MAX_PUBLICATION_TITLE_LENGTH),
    ],
)
def test_invalid_title_family_and_text_are_rejected(title: str) -> None:
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(valid_record(title=title))


def test_title_whitespace_unicode_and_comparison_prose_are_normalized() -> None:
    record = valid_record(title="  Anomali Cyber Watch:  تحليل أمني < 1.3  ")
    candidate = adapt_anomali_publication(record)

    assert candidate.canonical_title == "Anomali Cyber Watch: تحليل أمني < 1.3"


@pytest.mark.parametrize("levels", [1, 2, 4, MAX_ANOMALI_ENTITY_DECODE_PASSES + 1])
def test_nested_entity_encoded_script_titles_are_rejected(levels: int) -> None:
    title = "Anomali Cyber Watch: " + encode_entities(
        "<script>alert(1)</script>", levels
    )

    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(valid_record(title=title))


@pytest.mark.parametrize(
    "url",
    [
        "http://www.anomali.com/blog/anomali-cyber-watch-example",
        "https://anomali.com/blog/anomali-cyber-watch-example",
        "https://blog.anomali.com/blog/anomali-cyber-watch-example",
        "https://www.anomali.com.evil.example/blog/anomali-cyber-watch-example",
        "https://evil-anomali.com/blog/anomali-cyber-watch-example",
        "https://www.anomali.com./blog/anomali-cyber-watch-example",
        "https://192.0.2.1/blog/anomali-cyber-watch-example",
        "https://user:secret@www.anomali.com/blog/anomali-cyber-watch-example",
        "https://@www.anomali.com/blog/anomali-cyber-watch-example",
        "https://www.anomali.com:444/blog/anomali-cyber-watch-example",
        "https://www.anomali.com/blog/anomali-cyber-watch-example#fragment",
        "https://www.anomali.com/blog/anomali-cyber-watch-example;param",
        "https://www.anomali.com/blog/anomali-cyber-watch-%65xample",
        "https://www.anomali.com/blog/anomali-cyber-watch-%2Fexample",
        "https://www.anomali.com/blog/anomali-cyber-watch-%2e%2e",
        "https://www.anomali.com/blog/anomali-cyber-watch-example\\other",
        "https://www.anomali.com/blog/../blog/anomali-cyber-watch-example",
        "https://www.anomali.com/blog/anomali-cyber-watch-",
        "https://www.anomali.com/blog/",
        "https://www.anomali.com/blog/general-post",
        "https://www.anomali.com/products/threatstream",
        "https://www.anomali.com/marketplace/example",
        "https://www.anomali.com/resources/example",
        "https://www.anomali.com/download/example",
        "https：//www.anomali.com/blog/anomali-cyber-watch-example",
        "https://www.anomali.com/blog/anomali-cyber-watch-bad\ufffdslug",
        "https://www.anomali.com/blog/anomali-cyber-watch-example?token=secret",
        "https://www.anomali.com/blog/anomali-cyber-watch-example?signature=secret",
        "https://www.anomali.com/blog/anomali-cyber-watch-example?page=1",
    ],
)
def test_unapproved_urls_are_rejected_without_disclosure(url: str) -> None:
    with pytest.raises(AnomaliPublicationRecordError) as exc_info:
        adapt_anomali_publication(valid_record(url=url))

    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


def test_tracking_and_trailing_slash_variants_share_canonical_identity() -> None:
    base = "https://www.anomali.com/blog/anomali-cyber-watch-example"
    first = adapt_anomali_publication(valid_record(url=base))
    second = adapt_anomali_publication(valid_record(url=f"{base}/"))
    tracked = adapt_anomali_publication(
        valid_record(url=f"{base}/?utm_source=test&gclid=value")
    )

    assert first.canonical_url == base
    assert second.canonical_url == base
    assert tracked.canonical_url == base
    assert first.source_external_id == second.source_external_id
    assert first.source_external_id == tracked.source_external_id


@pytest.mark.parametrize(
    "url",
    [
        "https://www.anomali.com/blog/anomali-cyber-watch-example//",
        "https://www.anomali.com/blog/anomali-cyber-watch-example////",
        "https://www.anomali.com/blog//anomali-cyber-watch-example",
        "https://www.anomali.com/blog/anomali-cyber-watch-example//?utm_source=test",
    ],
)
def test_repeated_article_path_separators_are_rejected_without_echo(
    url: str,
) -> None:
    with pytest.raises(AnomaliPublicationRecordError) as exc_info:
        adapt_anomali_publication(valid_record(url=url))

    assert url not in str(exc_info.value)


@pytest.mark.parametrize(
    "summary",
    [
        "<p>body</p>",
        "&lt;iframe&gt;secret&lt;/iframe&gt;",
        "<style>secret</style>",
        "<object>secret</object>",
        "<embed src=x>",
        "<svg onload=x>",
        "bad\x00text",
        "\ud800",
        "x" * (MAX_PUBLICATION_SUMMARY_LENGTH + 1),
    ],
)
def test_unsafe_or_overlong_summary_is_rejected(summary: str) -> None:
    record = valid_record()
    record["summary"] = summary
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


def test_null_and_normal_unicode_summaries_are_supported() -> None:
    null_record = valid_record()
    null_record["summary"] = None
    unicode_record = valid_record()
    unicode_record["summary"] = "ملخص أعده المشغل"

    assert adapt_anomali_publication(null_record).summary is None
    assert adapt_anomali_publication(unicode_record).summary == "ملخص أعده المشغل"


@pytest.mark.parametrize(
    "markup",
    [
        "<script>alert(1)</script>",
        "<iframe src=x></iframe>",
        "<object>payload</object>",
        "<embed src=x>",
    ],
)
@pytest.mark.parametrize("levels", [2, 4, MAX_ANOMALI_ENTITY_DECODE_PASSES + 1])
def test_nested_entity_encoded_summary_markup_is_rejected(
    markup: str,
    levels: int,
) -> None:
    record = valid_record()
    record["summary"] = encode_entities(markup, levels)

    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


@pytest.mark.parametrize("field", ["authors", "categories"])
def test_nested_entity_encoded_list_markup_is_rejected(field: str) -> None:
    record = valid_record()
    record[field] = [encode_entities("<iframe>payload</iframe>", 4)]

    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


def test_benign_entities_unicode_ampersands_and_comparison_prose_are_supported() -> None:
    record = valid_record(title="Anomali Cyber Watch: Research &amp; Analysis")
    record["summary"] = "تحليل آمن &amp; comparison value < 1.3"
    record["authors"] = ["Research &amp; Analysis", "محلل"]

    candidate = adapt_anomali_publication(record)

    assert candidate.canonical_title == "Anomali Cyber Watch: Research & Analysis"
    assert candidate.summary == "تحليل آمن & comparison value < 1.3"
    assert candidate.safe_source_payload["authors"] == (
        "Research & Analysis",
        "محلل",
    )


@pytest.mark.parametrize(
    "published_at",
    [None, True, 0, "2026-01-27T00:00:00", "2026-02-30T00:00:00Z", "bad"],
)
def test_invalid_required_timestamps_are_rejected(published_at: object) -> None:
    record = valid_record()
    record["published_at"] = published_at
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


def test_timestamps_normalize_to_utc_and_reject_invalid_order() -> None:
    record = valid_record()
    record["published_at"] = "2026-01-27T04:00:00+04:00"
    record["modified_at"] = "2026-01-27T05:00:00+04:00"
    candidate = adapt_anomali_publication(record)

    assert candidate.source_published_at == datetime(2026, 1, 27, tzinfo=UTC)
    assert candidate.source_modified_at == datetime(2026, 1, 27, 1, tzinfo=UTC)
    record["modified_at"] = "2026-01-26T23:59:59Z"
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)

    record["modified_at"] = "not-a-timestamp"
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authors", ["a"] * (MAX_ANOMALI_AUTHORS + 1)),
        ("categories", ["c"] * (MAX_ANOMALI_CATEGORIES + 1)),
        ("authors", ["a" * 201]),
        ("categories", ["c" * 101]),
        ("authors", [1]),
        ("categories", [{"name": "nested"}]),
        ("authors", ["<b>author</b>"]),
        ("categories", ["bad\x01category"]),
        ("authors", ["\ud800"]),
    ],
)
def test_invalid_author_and_category_lists_are_rejected(
    field: str,
    value: object,
) -> None:
    record = valid_record()
    record[field] = value
    with pytest.raises(AnomaliPublicationRecordError):
        adapt_anomali_publication(record)


def test_empty_lists_and_stable_normalized_deduplication_are_supported() -> None:
    empty = valid_record()
    empty["authors"] = []
    empty["categories"] = []
    assert adapt_anomali_publication(empty).safe_source_payload == {
        "authors": (),
        "categories": (),
    }

    duplicate = valid_record()
    duplicate["authors"] = [" Analyst ", "Analyst", "محلل"]
    duplicate["categories"] = [" Cyber Watch ", "Cyber Watch"]
    candidate = adapt_anomali_publication(duplicate)
    assert candidate.safe_source_payload["authors"] == ("Analyst", "محلل")
    assert candidate.safe_source_payload["categories"] == ("Cyber Watch",)


def test_maximum_author_and_category_counts_are_accepted() -> None:
    record = valid_record()
    record["authors"] = [f"author-{index}" for index in range(MAX_ANOMALI_AUTHORS)]
    record["categories"] = [
        f"category-{index}" for index in range(MAX_ANOMALI_CATEGORIES)
    ]

    candidate = adapt_anomali_publication(record)

    assert len(candidate.safe_source_payload["authors"]) == MAX_ANOMALI_AUTHORS
    assert len(candidate.safe_source_payload["categories"]) == MAX_ANOMALI_CATEGORIES


def test_explicit_default_https_port_is_canonicalized() -> None:
    candidate = adapt_anomali_publication(
        valid_record(
            url=(
                "HTTPS://WWW.ANOMALI.COM:443/"
                "blog/anomali-cyber-watch-example/"
            )
        )
    )

    assert candidate.canonical_url == (
        "https://www.anomali.com/blog/anomali-cyber-watch-example"
    )


def test_identity_is_deterministic_url_owned_and_bounded() -> None:
    first = adapt_anomali_publication(valid_record(title="Anomali Cyber Watch: One"))
    renamed = adapt_anomali_publication(valid_record(title="Anomali Cyber Watch: Two"))
    different = adapt_anomali_publication(
        valid_record(
            url="https://www.anomali.com/blog/anomali-cyber-watch-different"
        )
    )

    assert first.source_external_id == renamed.source_external_id
    assert first.source_external_id == derive_anomali_external_id(first.canonical_url)
    assert first.source_external_id.startswith(f"{ANOMALI_SOURCE_SLUG}:url-sha256:")
    assert len(first.source_external_id) <= MAX_PUBLICATION_EXTERNAL_ID_LENGTH
    assert first.source_external_id != different.source_external_id
