from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ingestion.adapters.official_rss_publications import (
    MAX_FEED_ENTRIES,
    OfficialRssConflictError,
    OfficialRssPublicationError,
    OfficialRssXmlError,
    adapt_official_rss_feed,
    build_official_rss_cursor,
    parse_official_rss_cursor,
)


FIXTURES = Path(__file__).parent / "fixtures" / "c05"


@pytest.mark.parametrize(
    "source_slug,fixture,expected_id,language",
    [
        (
            "cert-fr-security-alerts",
            "cert-fr-alerts.xml",
            "CERTFR-2026-ALE-001",
            "fr",
        ),
        (
            "cert-fr-security-advisories",
            "cert-fr-advisories.xml",
            "CERTFR-2026-AVI-0001",
            "fr",
        ),
        (
            "uk-ncsc-threat-reports",
            "uk-ncsc-threat-reports.xml",
            "synthetic-weekly-threat-report",
            "en-GB",
        ),
    ],
)
def test_fixtures_normalize_only_safe_bounded_metadata(
    source_slug, fixture, expected_id, language
):
    document = adapt_official_rss_feed(
        source_slug,
        (FIXTURES / fixture).read_bytes(),
    )
    assert document.entries_received == document.records_accepted == 1
    assert document.records_rejected == 0
    candidate = document.candidates[0]
    assert candidate.source_external_id == expected_id
    assert candidate.safe_source_payload["language"] == language
    assert candidate.safe_source_payload["metadata_only"] is True
    assert "<" not in (candidate.summary or "")
    assert "script" not in (candidate.summary or "").lower()
    assert "enclosure" not in candidate.safe_source_payload
    assert ".pdf" not in str(candidate.safe_source_payload).lower()
    cursor = build_official_rss_cursor(document)
    parsed_hash, parsed_time = parse_official_rss_cursor(cursor)
    assert parsed_hash == document.canonical_metadata_hash
    assert parsed_time == document.greatest_publication_timestamp
    assert len(cursor) < 500


def test_exact_duplicates_are_deduplicated_but_conflicts_fail():
    body = (FIXTURES / "cert-fr-alerts.xml").read_bytes()
    item = body.split(b"<item>", 1)[1].split(b"</item>", 1)[0]
    duplicated = body.replace(b"</channel>", b"<item>" + item + b"</item></channel>")
    document = adapt_official_rss_feed("cert-fr-security-alerts", duplicated)
    assert document.entries_received == 2
    assert document.records_accepted == 1
    assert document.records_rejected == 0

    conflicting = duplicated.replace(
        b"Alerte de s\xc3\xa9curit\xc3\xa9 synth\xc3\xa9tique",
        b"Titre conflictuel",
        1,
    )
    with pytest.raises(OfficialRssConflictError):
        adapt_official_rss_feed("cert-fr-security-alerts", conflicting)


@pytest.mark.parametrize(
    "replacement",
    [
        b"https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/?x=1",
        b"https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/#fragment",
        b"https://user@www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/",
        b"https://www.cert.ssi.gouv.fr:443/alerte/CERTFR-2026-ALE-001/",
        b"https://www.cert.ssi.gouv.fr/alerte/../CERTFR-2026-ALE-001/",
        b"https://www.cert.ssi.gouv.fr/alerte/%2e%2e/CERTFR-2026-ALE-001/",
        b"http://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/",
        b"https://evil.example/alerte/CERTFR-2026-ALE-001/",
    ],
)
def test_unapproved_canonical_urls_are_rejected_without_rewrite(replacement):
    body = (FIXTURES / "cert-fr-alerts.xml").read_bytes().replace(
        b"https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/",
        replacement,
    )
    document = adapt_official_rss_feed("cert-fr-security-alerts", body)
    assert document.records_accepted == 0
    assert document.records_rejected == 1
    assert document.retained_rejections == ("invalid_entry",)


@pytest.mark.parametrize(
    "body",
    [
        b"<rss><channel>",
        b'<?xml version="1.0"?><!DOCTYPE rss><rss><channel/></rss>',
        b'<?xml version="1.0"?><!ENTITY x "unsafe"><rss><channel/></rss>',
        b'<?xml version="1.0"?><?xml-stylesheet href="https://evil.example/x"?><rss><channel/></rss>',
    ],
)
def test_malformed_or_unsafe_xml_fails_closed(body):
    with pytest.raises(OfficialRssXmlError):
        adapt_official_rss_feed("cert-fr-security-alerts", body)


def test_excessive_entry_count_fails_without_truncation():
    item = b"""
    <item><title>Synthetic</title>
    <link>https://www.ncsc.gov.uk/report/synthetic-report</link>
    <pubDate>Mon, 03 Aug 2026 12:00:00 +0000</pubDate></item>
    """
    body = b"<rss><channel>" + item * (MAX_FEED_ENTRIES + 1) + b"</channel></rss>"
    with pytest.raises(OfficialRssXmlError, match="entry limit"):
        adapt_official_rss_feed("uk-ncsc-threat-reports", body)


def test_author_and_category_bounds_produce_partial_document():
    body = (FIXTURES / "cert-fr-alerts.xml").read_bytes().replace(
        b"CERT-FR</author>",
        b"x" * 201 + b"</author>",
    )
    document = adapt_official_rss_feed("cert-fr-security-alerts", body)
    assert document.records_accepted == 0
    assert document.records_rejected == 1
    assert document.canonical_metadata_hash


def test_metadata_hash_is_deterministic_for_the_same_feed():
    body = (FIXTURES / "uk-ncsc-threat-reports.xml").read_bytes()
    first = adapt_official_rss_feed("uk-ncsc-threat-reports", body)
    second = adapt_official_rss_feed("uk-ncsc-threat-reports", body)
    assert first.canonical_metadata_hash == second.canonical_metadata_hash
    assert build_official_rss_cursor(first) == build_official_rss_cursor(second)


def test_cursor_accepts_an_explicit_effective_timestamp_or_both_absent():
    document = adapt_official_rss_feed(
        "uk-ncsc-threat-reports",
        (FIXTURES / "uk-ncsc-threat-reports.xml").read_bytes(),
    )
    retained = datetime(2026, 8, 5, 12, tzinfo=UTC)
    cursor = build_official_rss_cursor(
        replace(document, greatest_publication_timestamp=None),
        effective_timestamp=retained,
    )
    parsed_hash, parsed_timestamp = parse_official_rss_cursor(cursor)
    assert parsed_hash == document.canonical_metadata_hash
    assert parsed_timestamp == retained

    absent = build_official_rss_cursor(
        replace(document, greatest_publication_timestamp=None),
        effective_timestamp=None,
    )
    assert absent.endswith(":-")
    assert parse_official_rss_cursor(absent)[1] is None


def test_cursor_parser_rejects_noncanonical_or_oversized_values():
    with pytest.raises(OfficialRssPublicationError, match="cursor is invalid"):
        parse_official_rss_cursor("v1:not-a-hash:-")
    with pytest.raises(OfficialRssPublicationError, match="cursor is invalid"):
        parse_official_rss_cursor("v1:" + "a" * 64 + ":" + "x" * 500)
