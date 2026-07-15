from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from app.ingestion.adapters import ibm_x_force_publications
from app.ingestion.adapters.ibm_x_force_publications import (
    IBM_X_FORCE_OSINT_POLICY,
    IBM_X_FORCE_OSINT_SOURCE_SLUG,
    IBM_X_FORCE_RESEARCH_POLICY,
    IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
    IBM_X_FORCE_SOURCE_POLICIES,
    MAX_IBM_X_FORCE_AUTHORS,
    MAX_IBM_X_FORCE_CATEGORIES,
    MAX_IBM_X_FORCE_ENTITY_DECODE_PASSES,
    MAX_IBM_X_FORCE_FILE_BYTES,
    MAX_IBM_X_FORCE_PUBLICATIONS,
    IbmXForcePublicationFileError,
    IbmXForcePublicationRecordError,
    adapt_ibm_x_force_osint_advisory,
    adapt_ibm_x_force_publication,
    adapt_ibm_x_force_research_publication,
    derive_ibm_x_force_external_id,
    load_ibm_x_force_publication_file,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    PublicationCandidate,
    normalize_publication_candidate,
)


RESEARCH_URL = "https://www.ibm.com/think/x-force/example-threat-research"
OSINT_GUID = "0123456789abcdef0123456789abcdef"
OSINT_URL = f"https://exchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}"


def valid_record(source_slug: str = IBM_X_FORCE_RESEARCH_SOURCE_SLUG) -> dict[str, object]:
    return {
        "title": "Example IBM X-Force publication",
        "url": RESEARCH_URL if source_slug == IBM_X_FORCE_RESEARCH_SOURCE_SLUG else OSINT_URL,
        "summary": "Operator-prepared plain-text metadata summary.",
        "published_at": "2026-01-20T00:00:00Z",
        "modified_at": None,
        "authors": ["Example Author"],
        "categories": ["Threat intelligence"],
    }


def valid_document(
    source_slug: str = IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
    publications: list[object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_slug": source_slug,
        "publications": (
            [valid_record(source_slug)] if publications is None else publications
        ),
    }


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def encode_entities(value: str, levels: int) -> str:
    for _ in range(levels):
        value = escape(value)
    return value


def create_symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Symlink creation unavailable: {type(exc).__name__}")


@pytest.mark.parametrize(
    ("source_slug", "expected_url", "item_type"),
    [
        (IBM_X_FORCE_RESEARCH_SOURCE_SLUG, RESEARCH_URL, "threat_report"),
        (IBM_X_FORCE_OSINT_SOURCE_SLUG, OSINT_URL, "security_advisory"),
    ],
)
def test_valid_documents_are_immutable_source_specific_candidates(
    tmp_path: Path,
    source_slug: str,
    expected_url: str,
    item_type: str,
) -> None:
    document = load_ibm_x_force_publication_file(
        write_json(tmp_path / "ibm.json", valid_document(source_slug))
    )
    record = document.publications[0]
    candidate = adapt_ibm_x_force_publication(document.source_slug, record)

    assert document.source_slug == source_slug
    assert isinstance(document.publications, tuple)
    assert isinstance(record, MappingProxyType)
    assert record["authors"] == ("Example Author",)  # type: ignore[index]
    with pytest.raises(TypeError):
        record["title"] = "changed"  # type: ignore[index]
    assert candidate.source_slug == source_slug
    assert candidate.canonical_url == expected_url
    assert normalize_publication_candidate(candidate).item_type == item_type


def test_source_policies_are_explicit_and_immutable() -> None:
    assert IBM_X_FORCE_SOURCE_POLICIES == {
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG: IBM_X_FORCE_RESEARCH_POLICY,
        IBM_X_FORCE_OSINT_SOURCE_SLUG: IBM_X_FORCE_OSINT_POLICY,
    }
    with pytest.raises(TypeError):
        IBM_X_FORCE_SOURCE_POLICIES["other"] = IBM_X_FORCE_RESEARCH_POLICY  # type: ignore[index]
    with pytest.raises(AttributeError):
        IBM_X_FORCE_RESEARCH_POLICY.source_slug = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "source_slug": IBM_X_FORCE_RESEARCH_SOURCE_SLUG, "publications": []},
        {"schema_version": True, "source_slug": IBM_X_FORCE_RESEARCH_SOURCE_SLUG, "publications": []},
        {"schema_version": 1, "source_slug": IBM_X_FORCE_RESEARCH_SOURCE_SLUG},
        {**valid_document(), "extra": None},
        {**valid_document(), "source_slug": "ibm-x-force-exchange"},
        {**valid_document(), "source_slug": []},
        {**valid_document(), "publications": {}},
    ],
)
def test_invalid_document_envelopes_are_rejected(tmp_path: Path, payload: object) -> None:
    with pytest.raises(IbmXForcePublicationFileError):
        load_ibm_x_force_publication_file(write_json(tmp_path / "invalid.json", payload))


@pytest.mark.parametrize(
    "source_slug",
    [IBM_X_FORCE_RESEARCH_SOURCE_SLUG, IBM_X_FORCE_OSINT_SOURCE_SLUG],
)
def test_empty_and_maximum_catalogues_are_accepted(
    tmp_path: Path,
    source_slug: str,
) -> None:
    empty = load_ibm_x_force_publication_file(
        write_json(tmp_path / "empty.json", valid_document(source_slug, []))
    )
    maximum = load_ibm_x_force_publication_file(
        write_json(
            tmp_path / "maximum.json",
            valid_document(source_slug, [{}] * MAX_IBM_X_FORCE_PUBLICATIONS),
        )
    )
    assert empty.publications == ()
    assert len(maximum.publications) == MAX_IBM_X_FORCE_PUBLICATIONS


def test_malformed_duplicate_keys_constants_and_depth_are_rejected(tmp_path: Path) -> None:
    files = {
        "malformed": "{",
        "duplicate-root": (
            '{"schema_version":1,"schema_version":1,'
            '"source_slug":"ibm-x-force-public-research","publications":[]}'
        ),
        "duplicate-record": (
            '{"schema_version":1,"source_slug":"ibm-x-force-public-research",'
            '"publications":[{"title":"one","title":"two"}]}'
        ),
        "nan": (
            '{"schema_version":1,"source_slug":"ibm-x-force-public-research",'
            '"publications":[NaN]}'
        ),
        "infinity": (
            '{"schema_version":1,"source_slug":"ibm-x-force-public-research",'
            '"publications":[-Infinity]}'
        ),
        "positive-infinity": (
            '{"schema_version":1,"source_slug":"ibm-x-force-public-research",'
            '"publications":[Infinity]}'
        ),
        "deep": "[" * 10 + "]" * 10,
    }
    for name, text in files.items():
        path = tmp_path / f"{name}.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(IbmXForcePublicationFileError):
            load_ibm_x_force_publication_file(path)


def test_invalid_utf8_bom_oversize_and_record_limit_are_rejected(tmp_path: Path) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(valid_document()).encode())
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_IBM_X_FORCE_FILE_BYTES + 1))
    too_many = write_json(
        tmp_path / "too-many.json",
        valid_document(publications=[{}] * (MAX_IBM_X_FORCE_PUBLICATIONS + 1)),
    )
    for path in (invalid_utf8, bom, oversized, too_many):
        with pytest.raises(IbmXForcePublicationFileError):
            load_ibm_x_force_publication_file(path)


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\catalogue.json",
        "//server/share/catalogue.json",
        r"\\?\UNC\server\share\catalogue.json",
        r"\\.\pipe\ibm-catalogue",
        r"\??\C:\catalogue.json",
        r"\Device\HarddiskVolumeShadowCopy1\catalogue.json",
        "https://www.ibm.com/catalogue.json",
    ],
)
def test_remote_device_pipe_and_http_paths_are_rejected_before_traversal(
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ibm_x_force_publications.Path,
        "lstat",
        lambda *_: pytest.fail("filesystem traversal must not occur"),
    )
    with pytest.raises(IbmXForcePublicationFileError) as exc_info:
        load_ibm_x_force_publication_file(path)
    assert path not in str(exc_info.value)


def test_missing_directory_and_symlink_paths_are_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    for path in (tmp_path / "missing.json", directory):
        with pytest.raises(IbmXForcePublicationFileError) as exc_info:
            load_ibm_x_force_publication_file(path)
        assert str(path) not in str(exc_info.value)

    target = write_json(tmp_path / "target.json", valid_document())
    file_link = tmp_path / "file-link.json"
    create_symlink_or_skip(file_link, target, directory=False)
    with pytest.raises(IbmXForcePublicationFileError):
        load_ibm_x_force_publication_file(file_link)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    write_json(real_parent / "data.json", valid_document())
    parent_link = tmp_path / "parent-link"
    create_symlink_or_skip(parent_link, real_parent, directory=True)
    with pytest.raises(IbmXForcePublicationFileError):
        load_ibm_x_force_publication_file(parent_link / "data.json")


def test_descriptor_identity_growth_and_close_failures_are_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = write_json(tmp_path / "expected.json", valid_document())
    replacement = write_json(tmp_path / "replacement.json", valid_document(publications=[]))
    real_open = os.open
    monkeypatch.setattr(
        ibm_x_force_publications.os,
        "open",
        lambda _path, flags: real_open(replacement, flags),
    )
    with pytest.raises(IbmXForcePublicationFileError):
        load_ibm_x_force_publication_file(expected)
    monkeypatch.undo()

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
            st_size=MAX_IBM_X_FORCE_FILE_BYTES + 1,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns,
            st_ino=metadata.st_ino,
            st_dev=metadata.st_dev,
        )

    def tracking_fdopen(descriptor: int, mode: str):
        stream = real_fdopen(descriptor, mode)
        streams.append(stream)
        return stream

    monkeypatch.setattr(ibm_x_force_publications.os, "fstat", growing_fstat)
    monkeypatch.setattr(ibm_x_force_publications.os, "fdopen", tracking_fdopen)
    with pytest.raises(IbmXForcePublicationFileError):
        load_ibm_x_force_publication_file(expected)
    assert streams and all(stream.closed for stream in streams)
    monkeypatch.undo()

    real_close = os.close
    close_calls = 0

    def fail_fstat(descriptor: int):
        del descriptor
        raise OSError("SECRET descriptor inspection")

    def close_then_fail(descriptor: int) -> None:
        nonlocal close_calls
        close_calls += 1
        real_close(descriptor)
        raise OSError("SECRET descriptor close")

    monkeypatch.setattr(ibm_x_force_publications.os, "fstat", fail_fstat)
    monkeypatch.setattr(ibm_x_force_publications.os, "close", close_then_fail)
    with pytest.raises(IbmXForcePublicationFileError) as exc_info:
        load_ibm_x_force_publication_file(expected)
    assert close_calls == 1
    assert "SECRET" not in str(exc_info.value)


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        {**valid_record(), "content": "article body"},
        {**valid_record(), "iocs": ["192.0.2.1"]},
        {**valid_record(), "api_response": {}},
        {key: value for key, value in valid_record().items() if key != "summary"},
        {**valid_record(), "title": 1},
        {**valid_record(), "summary": []},
        {**valid_record(), "authors": "IBM"},
        {**valid_record(), "categories": {}},
    ],
)
def test_exact_record_schema_and_types_are_enforced(record: object) -> None:
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(record)


def test_cross_source_urls_and_dispatch_overrides_are_rejected() -> None:
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(valid_record(IBM_X_FORCE_OSINT_SOURCE_SLUG))
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_osint_advisory(valid_record(IBM_X_FORCE_RESEARCH_SOURCE_SLUG))
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_publication("ibm-x-force-exchange", valid_record())


def test_research_tracking_and_single_slash_share_canonical_identity() -> None:
    base = RESEARCH_URL
    first = adapt_ibm_x_force_research_publication(valid_record())
    slash_record = valid_record()
    slash_record["url"] = f"{base}/"
    tracked_record = valid_record()
    tracked_record["url"] = f"{base}/?utm_source=test&gclid=value"
    slash = adapt_ibm_x_force_research_publication(slash_record)
    tracked = adapt_ibm_x_force_research_publication(tracked_record)
    assert first.canonical_url == slash.canonical_url == tracked.canonical_url == base
    assert first.source_external_id == slash.source_external_id == tracked.source_external_id


@pytest.mark.parametrize(
    ("source_slug", "adapter", "authority", "path", "expected_url"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            authority,
            "/think/x-force/example-threat-research",
            RESEARCH_URL,
        )
        for authority in (
            "www.ibm.com",
            "www.ibm.com:443",
            "WWW.IBM.COM",
            "WWW.IBM.COM:443",
        )
    ]
    + [
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            authority,
            f"/osint/guid%3A{OSINT_GUID}",
            OSINT_URL,
        )
        for authority in (
            "exchange.xforce.ibmcloud.com",
            "exchange.xforce.ibmcloud.com:443",
            "EXCHANGE.XFORCE.IBMCLOUD.COM",
            "EXCHANGE.XFORCE.IBMCLOUD.COM:443",
        )
    ],
)
def test_only_exact_raw_authorities_are_accepted(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    authority: str,
    path: str,
    expected_url: str,
) -> None:
    record = valid_record(source_slug)
    record["url"] = f"https://{authority}{path}"

    candidate = adapter(record)

    assert candidate.canonical_url == expected_url


@pytest.mark.parametrize(
    ("source_slug", "adapter", "host", "path"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            "www.ibm.com",
            "/think/x-force/example-threat-research",
        ),
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            "exchange.xforce.ibmcloud.com",
            f"/osint/guid%3A{OSINT_GUID}",
        ),
    ],
)
@pytest.mark.parametrize(
    "authority_template",
    [
        "{host}:",
        "{host}:0443",
        "{host}:+443",
        "{host}:443.",
        "{host}: 443",
        "{host}:443 ",
        "{host}::443",
        "@{host}",
        "user@{host}",
        "user:password@{host}",
        "{host}.",
        "{host}:444",
    ],
)
def test_malformed_or_noncanonical_raw_authorities_are_rejected(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    host: str,
    path: str,
    authority_template: str,
) -> None:
    record = valid_record(source_slug)
    url = f"https://{authority_template.format(host=host)}{path}"
    record["url"] = url

    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapter(record)

    assert url not in str(exc_info.value)
    assert "password" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("source_slug", "adapter", "base_url"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            RESEARCH_URL,
        ),
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            OSINT_URL,
        ),
    ],
)
@pytest.mark.parametrize(
    "suffix",
    ["#fragment", "#", "#/path", "?#", "?utm_source=test#"],
)
def test_any_raw_fragment_delimiter_is_rejected(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    base_url: str,
    suffix: str,
) -> None:
    record = valid_record(source_slug)
    url = f"{base_url}{suffix}"
    record["url"] = url

    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapter(record)

    assert url not in str(exc_info.value)


@pytest.mark.parametrize(
    ("source_slug", "adapter", "base_url"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            RESEARCH_URL,
        ),
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            OSINT_URL,
        ),
    ],
)
def test_tracking_queries_remain_canonical_and_identity_stable(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    base_url: str,
) -> None:
    candidates = []
    for suffix in (
        "",
        "?utm_source=test",
        "?utm_source=",
        "?utm_source=test-value",
        "?utm_source=test_value",
        "?utm_source=test.value",
        "?utm_source=test~value",
        "?utm_source=test&utm_medium=manual",
        "?utm_source=test&gclid=value_123",
    ):
        record = valid_record(source_slug)
        record["url"] = f"{base_url}{suffix}"
        candidates.append(adapter(record))

    assert {candidate.canonical_url for candidate in candidates} == {base_url}
    assert len({candidate.source_external_id for candidate in candidates}) == 1


@pytest.mark.parametrize(
    ("source_slug", "adapter", "base_url"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            RESEARCH_URL,
        ),
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            OSINT_URL,
        ),
    ],
)
@pytest.mark.parametrize(
    "query",
    [
        "?",
        "/?",
        "?&",
        "?&&",
        "?utm_source=test&",
        "?utm_source=test&&gclid=value",
        "?utm_source",
        "?=value",
        "?utm_source=test&=value",
        "?utm_source=test?gclid=value",
        "?page=1",
        "?signature=secret",
        "?token=secret",
        "?session=secret",
        "?sessiontoken=secret",
        "?password=secret",
        "?api_key=secret",
        "?private=secret",
    ],
)
def test_empty_malformed_or_unapproved_queries_are_rejected(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    base_url: str,
    query: str,
) -> None:
    record = valid_record(source_slug)
    url = f"{base_url}{query}"
    record["url"] = url

    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapter(record)

    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("source_slug", "adapter", "base_url"),
    [
        (
            IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
            adapt_ibm_x_force_research_publication,
            RESEARCH_URL,
        ),
        (
            IBM_X_FORCE_OSINT_SOURCE_SLUG,
            adapt_ibm_x_force_osint_advisory,
            OSINT_URL,
        ),
    ],
)
@pytest.mark.parametrize(
    "query",
    [
        "?utm_source=x%2526token%253Dsecret",
        "?utm_source=x%253Btoken%253Dsecret",
        "?utm_source=x%2526password%253Dsecret",
        "?utm_source=x%2526api_key%253Dsecret",
        "?utm_source=x%2526signature%253Dsecret",
        "?utm_source=x%2526session%253Dsecret",
        "?utm_source=x;token=secret",
        "?utm_source=x;password=secret",
        "?utm_source=x;api_key=secret",
        "?utm_source=x;signature=secret",
        "?utm_source=x;session=secret",
        "?utm_source=x%3Btoken%3Dsecret",
        "?utm_source=x%26token%3Dsecret",
        "?utm_source=x%EF%BC%86token%EF%BC%9Dsecret",
        "?utm_source=%",
        "?utm_source=%0",
        "?utm_source=%Z0",
        "?utm_source=%0Z",
        "?utm_source=%ZZ",
        "?utm_source=%25ZZ",
        "?utm_source=%00",
        "?utm_source=%09",
        "?utm_source=%0A",
        "?utm_source=%0D",
        "?utm_source=%1F",
        "?utm_source=%7F",
        "?utm_source=%EF%BF%BD",
        "?utm_source=%ED%A0%80",
        "?utm_source=test+value",
        "?utm_source=test%20value",
        "?utm_source=a=b",
        "?utm_source=test/value",
        "?utm_source=test:value",
        "?utm_source=test@value",
        "?utm_source=test value",
        "?utm_source=العربية",
        "?utm_source=raw\x00control",
        "?utm_source=raw\tcontrol",
        "?utm_source=raw\ncontrol",
        "?utm_source=raw\rcontrol",
        "?utm_source=raw\x1fcontrol",
        "?utm_source=raw\x7fcontrol",
    ],
)
def test_unsupported_raw_tracking_queries_are_rejected_without_echo(
    source_slug: str,
    adapter: Callable[[object], PublicationCandidate],
    base_url: str,
    query: str,
) -> None:
    record = valid_record(source_slug)
    url = f"{base_url}{query}"
    record["url"] = url

    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapter(record)

    message = str(exc_info.value)
    assert url not in message
    assert query not in message
    assert "secret" not in message.lower()
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "url",
    [
        "https://www.ibm.com/think/x-force",
        "https://www.ibm.com/think/x-force/",
        f"{RESEARCH_URL}//",
        "https://www.ibm.com/think//x-force/example",
        "https://www.ibm.com/think/x-force/Example",
        "https://www.ibm.com/think/x-force/example_slug",
        "https://www.ibm.com/think/x-force/example--slug",
        "https://www.ibm.com/think/x-force/example.pdf",
        "https://www.ibm.com/think/x-force/%65xample",
        "https://www.ibm.com/think/x-force/../example",
        "http://www.ibm.com/think/x-force/example",
        "https://ibm.com/think/x-force/example",
        "https://research.ibm.com/think/x-force/example",
        "https://www.ibm.com.evil.example/think/x-force/example",
        "https://%77ww.ibm.com/think/x-force/example",
        "https://www.ibm.com./think/x-force/example",
        "https://192.0.2.1/think/x-force/example",
        "https://user:secret@www.ibm.com/think/x-force/example",
        "https://www.ibm.com:444/think/x-force/example",
        "https://www.ibm.com/think/x-force/example#fragment",
        "https://www.ibm.com/think/x-force/example;parameter",
        "https://www.ibm.com/think/x-force/example?page=1",
        "https://www.ibm.com/think/x-force/example?token=secret",
        "https://www.ibm.com/think/x-force/example?signature=secret",
        "https://www.ibm.com/reports/example",
        "https://www.ibm.com/services/example",
        "https://www.ibm.com/products/example",
        "https://www.ibm.com/think/topics/example",
        "https://www.ibm.com/newsroom/example",
        "https://www.ibm.com/downloads/example.pdf",
    ],
)
def test_unapproved_research_urls_are_rejected_without_echo(url: str) -> None:
    record = valid_record()
    record["url"] = url
    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapt_ibm_x_force_research_publication(record)
    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


def test_osint_separator_guid_case_tracking_and_slash_share_identity() -> None:
    variants = [
        OSINT_URL,
        f"https://exchange.xforce.ibmcloud.com/osint/guid%3a{OSINT_GUID.upper()}",
        f"{OSINT_URL}/",
        f"{OSINT_URL}/?utm_source=test&gclid=value",
    ]
    candidates = []
    for url in variants:
        record = valid_record(IBM_X_FORCE_OSINT_SOURCE_SLUG)
        record["url"] = url
        candidates.append(adapt_ibm_x_force_osint_advisory(record))
    assert {candidate.canonical_url for candidate in candidates} == {OSINT_URL}
    assert len({candidate.source_external_id for candidate in candidates}) == 1


@pytest.mark.parametrize(
    "url",
    [
        f"{OSINT_URL}//",
        f"https://exchange.xforce.ibmcloud.com/osint//guid%3A{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid:{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%2F{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%5C{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%2E{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%253A{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID[:-1]}",
        f"https://exchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}0",
        "https://exchange.xforce.ibmcloud.com/osint/guid%3Axyz",
        f"{OSINT_URL}/extra",
        f"https://www.ibm.com/osint/guid%3A{OSINT_GUID}",
        f"http://exchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com./osint/guid%3A{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com.evil.example/osint/guid%3A{OSINT_GUID}",
        f"https://%65xchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}",
        f"https://192.0.2.1/osint/guid%3A{OSINT_GUID}",
        f"https://ibmcloud.com/osint/guid%3A{OSINT_GUID}",
        f"https://integration.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}",
        f"https://user:secret@exchange.xforce.ibmcloud.com/osint/guid%3A{OSINT_GUID}",
        f"https://exchange.xforce.ibmcloud.com:444/osint/guid%3A{OSINT_GUID}",
        f"{OSINT_URL}#fragment",
        f"{OSINT_URL}?page=1",
        f"{OSINT_URL}?token=secret",
        f"{OSINT_URL}?signature=secret",
        "https://exchange.xforce.ibmcloud.com/ip/192.0.2.1",
        "https://exchange.xforce.ibmcloud.com/url/example.com",
        "https://exchange.xforce.ibmcloud.com/threats/example",
        "https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-2026-0001",
        "https://exchange.xforce.ibmcloud.com/search/example",
        "https://exchange.xforce.ibmcloud.com/api/example",
        "https://exchange.xforce.ibmcloud.com/settings/profile",
        "https://exchange.xforce.ibmcloud.com/hub/example",
        "https://exchange.xforce.ibmcloud.com/report/list",
        "https://exchange.xforce.ibmcloud.com/app-exchange/download/file",
    ],
)
def test_unapproved_osint_urls_are_rejected_without_echo(url: str) -> None:
    record = valid_record(IBM_X_FORCE_OSINT_SOURCE_SLUG)
    record["url"] = url
    with pytest.raises(IbmXForcePublicationRecordError) as exc_info:
        adapt_ibm_x_force_osint_advisory(record)
    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "<script>alert(1)</script>"),
        ("summary", "&lt;iframe&gt;payload&lt;/iframe&gt;"),
        ("summary", "<style>payload</style>"),
        ("summary", "<object>payload</object>"),
        ("summary", "<embed src=x>"),
        ("summary", "<svg onload=x>"),
        ("summary", "onclick=secret"),
        ("summary", "< malformed"),
        ("summary", "bad\x00text"),
        ("summary", "\ud800"),
        ("summary", "bad\ufffdtext"),
        ("title", "x" * (MAX_PUBLICATION_TITLE_LENGTH + 1)),
        ("summary", "x" * (MAX_PUBLICATION_SUMMARY_LENGTH + 1)),
        ("authors", ["a"] * (MAX_IBM_X_FORCE_AUTHORS + 1)),
        ("categories", ["c"] * (MAX_IBM_X_FORCE_CATEGORIES + 1)),
        ("authors", ["a" * 201]),
        ("categories", ["c" * 101]),
        ("authors", [1]),
        ("categories", [{"name": "nested"}]),
    ],
)
def test_unsafe_or_overlong_metadata_is_rejected(field: str, value: object) -> None:
    record = valid_record()
    record[field] = value
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(record)


def test_deeply_encoded_markup_is_rejected_across_metadata() -> None:
    for field in ("title", "summary"):
        record = valid_record()
        record[field] = encode_entities(
            "<script>alert(1)</script>",
            MAX_IBM_X_FORCE_ENTITY_DECODE_PASSES + 1,
        )
        with pytest.raises(IbmXForcePublicationRecordError):
            adapt_ibm_x_force_research_publication(record)


def test_benign_text_null_summary_and_stable_list_deduplication() -> None:
    record = valid_record()
    record["title"] = "تحليل IBM &amp; risk < 1.3"
    record["summary"] = None
    record["authors"] = [" Analyst ", "Analyst", "محلل"]
    record["categories"] = [" OSINT ", "OSINT"]
    candidate = adapt_ibm_x_force_research_publication(record)
    assert candidate.canonical_title == "تحليل IBM & risk < 1.3"
    assert candidate.summary is None
    assert candidate.safe_source_payload["authors"] == ("Analyst", "محلل")
    assert candidate.safe_source_payload["categories"] == ("OSINT",)


def test_maximum_author_and_category_counts_are_accepted() -> None:
    record = valid_record()
    record["authors"] = [f"author-{index}" for index in range(MAX_IBM_X_FORCE_AUTHORS)]
    record["categories"] = [
        f"category-{index}" for index in range(MAX_IBM_X_FORCE_CATEGORIES)
    ]
    candidate = adapt_ibm_x_force_research_publication(record)
    assert len(candidate.safe_source_payload["authors"]) == MAX_IBM_X_FORCE_AUTHORS
    assert len(candidate.safe_source_payload["categories"]) == MAX_IBM_X_FORCE_CATEGORIES


@pytest.mark.parametrize(
    "published_at",
    [None, True, 0, "2026-01-20T00:00:00", "2026-02-30T00:00:00Z", "bad"],
)
def test_invalid_published_timestamps_are_rejected(published_at: object) -> None:
    record = valid_record()
    record["published_at"] = published_at
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(record)


def test_timestamps_normalize_to_utc_and_modified_order_is_enforced() -> None:
    record = valid_record()
    record["published_at"] = "2026-01-20T04:00:00+04:00"
    record["modified_at"] = "2026-01-20T05:00:00+04:00"
    candidate = adapt_ibm_x_force_research_publication(record)
    assert candidate.source_published_at == datetime(2026, 1, 20, tzinfo=UTC)
    assert candidate.source_modified_at == datetime(2026, 1, 20, 1, tzinfo=UTC)
    record["modified_at"] = "2026-01-19T23:59:59Z"
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(record)
    record["modified_at"] = "not-a-timestamp"
    with pytest.raises(IbmXForcePublicationRecordError):
        adapt_ibm_x_force_research_publication(record)


def test_identity_is_exact_sha256_source_separated_and_metadata_independent() -> None:
    first_record = valid_record()
    first = adapt_ibm_x_force_research_publication(first_record)
    changed_record = valid_record()
    changed_record["title"] = "Renamed IBM publication"
    changed_record["summary"] = "Changed metadata"
    changed_record["authors"] = ["Changed Author"]
    changed_record["categories"] = ["Changed Category"]
    changed_record["published_at"] = "2026-01-21T00:00:00Z"
    changed = adapt_ibm_x_force_research_publication(changed_record)
    expected_digest = sha256(
        f"{IBM_X_FORCE_RESEARCH_SOURCE_SLUG}\n{RESEARCH_URL}".encode("utf-8")
    ).hexdigest()
    assert first.source_external_id == (
        f"{IBM_X_FORCE_RESEARCH_SOURCE_SLUG}:url-sha256:{expected_digest}"
    )
    assert first.source_external_id == changed.source_external_id
    assert len(first.source_external_id) <= MAX_PUBLICATION_EXTERNAL_ID_LENGTH
    assert derive_ibm_x_force_external_id(
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG, RESEARCH_URL
    ) != derive_ibm_x_force_external_id(IBM_X_FORCE_OSINT_SOURCE_SLUG, RESEARCH_URL)
    assert derive_ibm_x_force_external_id(
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG, RESEARCH_URL
    ) != derive_ibm_x_force_external_id(
        IBM_X_FORCE_RESEARCH_SOURCE_SLUG,
        "https://www.ibm.com/think/x-force/different-research",
    )
