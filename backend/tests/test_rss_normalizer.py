from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from time import struct_time

import pytest

from app.ingestion.normalizers.rss import (
    RssNormalizationError,
    canonicalize_advisory_url,
    deduplicate_rss_entries,
    normalize_rss_entry,
    normalize_rss_feed,
)


def rss_item(
    *,
    guid: str = "CERT-EU-SA2026-001",
    title: str = "CERT-EU Security Advisory",
    link: str = "https://cert.europa.eu/publications/security-advisories/2026-001?b=2&utm_source=x&a=1#g",
    description: str = "<p>Safe advisory &amp; summary.</p><script>secret()</script>",
    pub_date: str = "Wed, 08 Jul 2026 10:30:00 +0200",
) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>CERT-EU</title><item>
<guid>{guid}</guid>
<title>{title}</title>
<link>{link}</link>
<description>{description}</description>
<pubDate>{pub_date}</pubDate>
<category>Advisory</category>
</item></channel></rss>""".encode()


def atom_feed() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>CERT-EU</title>
<entry>
<id>tag:cert.europa.eu,2026:advisory-2</id>
<title>Atom advisory</title>
<link href="https://cert.europa.eu/publications/security-advisories/2026-002"/>
<summary><![CDATA[<b>Atom</b> summary<style>.x{}</style>]]></summary>
<updated>2026-07-08T08:30:00Z</updated>
</entry>
</feed>"""


def test_normalizes_rss_item_into_safe_allowlisted_fields() -> None:
    record = normalize_rss_feed(rss_item())[0]

    assert record.source_external_id == "CERT-EU-SA2026-001"
    assert record.canonical_title == "CERT-EU Security Advisory"
    assert record.summary == "Safe advisory & summary."
    assert record.canonical_url == (
        "https://cert.europa.eu/publications/security-advisories/2026-001?a=1&b=2"
    )
    assert record.source_published_at == datetime(2026, 7, 8, 8, 30, tzinfo=UTC)
    assert record.source_modified_at is None
    assert record.canonical_url_hash
    assert record.content_hash
    assert record.raw_payload == {
        "categories": ["Advisory"],
        "published": "Wed, 08 Jul 2026 10:30:00 +0200",
        "published_utc": "2026-07-08T08:30:00+00:00",
        "source_id": "CERT-EU-SA2026-001",
    }


def test_normalizes_atom_entries() -> None:
    record = normalize_rss_feed(atom_feed())[0]

    assert record.source_external_id == "tag:cert.europa.eu,2026:advisory-2"
    assert record.summary == "Atom summary"
    assert record.source_modified_at == datetime(2026, 7, 8, 8, 30, tzinfo=UTC)


def test_missing_guid_falls_back_to_url_hash_identifier() -> None:
    body = rss_item(guid="")

    record = normalize_rss_feed(body)[0]

    assert record.source_external_id.startswith("url-sha256:")


@pytest.mark.parametrize(
    "url",
    [
        "http://cert.europa.eu/publications/x",
        "https://example.com/publications/x",
        "https://user:pass@cert.europa.eu/publications/x",
        "https://cert.europa.eu:444/publications/x",
        "https://192.0.2.10/publications/x",
        "https://cert.europa.eu:bad/feed",
        "https://cert.europa.eu:999999/feed",
        "https://[invalid/feed",
    ],
)
def test_rejects_unapproved_advisory_urls(url: str) -> None:
    with pytest.raises(RssNormalizationError) as exc_info:
        canonicalize_advisory_url(url)
    assert url not in str(exc_info.value)


def test_rejects_invalid_dates() -> None:
    with pytest.raises(RssNormalizationError, match="date"):
        normalize_rss_feed(rss_item(pub_date="not-a-date"))


def test_rejects_non_representable_parsed_dates_safely() -> None:
    raw_date = "0000-01-01T00:00:00Z"

    with pytest.raises(RssNormalizationError, match="invalid date") as exc_info:
        normalize_rss_entry(
            {
                "id": "CERT-EU-SA2026-999",
                "title": "Invalid date advisory",
                "link": "https://cert.europa.eu/publications/security-advisories/invalid-date",
                "published": raw_date,
                "published_parsed": struct_time((0, 1, 1, 0, 0, 0, 0, 1, 0)),
            }
        )

    assert raw_date not in str(exc_info.value)


def test_hashes_are_deterministic() -> None:
    first = normalize_rss_feed(rss_item())[0]
    second = normalize_rss_feed(rss_item())[0]

    assert first.canonical_url_hash == second.canonical_url_hash
    assert first.content_hash == second.content_hash


def test_text_fields_are_bounded() -> None:
    record = normalize_rss_feed(rss_item(title="T" * 800, description="S" * 12_000))[0]

    assert len(record.canonical_title) == 500
    assert len(record.summary) == 10_000


def test_exact_duplicate_entries_are_collapsed() -> None:
    record = normalize_rss_feed(rss_item())[0]

    assert deduplicate_rss_entries([record, record]) == [record]


def test_conflicting_duplicate_external_id_is_rejected() -> None:
    first = normalize_rss_feed(rss_item())[0]
    second = replace(
        first,
        canonical_url="https://cert.europa.eu/publications/security-advisories/other",
        canonical_url_hash="b" * 64,
    )

    with pytest.raises(RssNormalizationError, match="duplicate"):
        deduplicate_rss_entries([first, second])


def test_conflicting_duplicate_url_hash_is_rejected() -> None:
    first = normalize_rss_feed(rss_item())[0]
    second = replace(first, source_external_id="other-id", content_hash="c" * 64)

    with pytest.raises(RssNormalizationError, match="duplicate"):
        deduplicate_rss_entries([first, second])
