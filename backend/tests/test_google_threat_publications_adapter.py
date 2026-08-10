from __future__ import annotations

from datetime import UTC, datetime
from time import struct_time

import pytest

from app.ingestion.adapters import google_threat_publications
from app.ingestion.adapters.google_threat_publications import (
    GOOGLE_AUTHOR_NAME,
    MANDIANT_AUTHOR_NAME,
    GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
    MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
    MAX_GOOGLE_THREAT_CATEGORIES,
    MAX_GOOGLE_THREAT_DIAGNOSTIC_BYTES,
    MAX_GOOGLE_THREAT_FEED_ENTRIES,
    GoogleThreatFeedError,
    GoogleThreatPublicationRecordError,
    adapt_google_threat_publication,
    derive_google_threat_external_id,
    parse_google_threat_feed_entries,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_SUMMARY_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    PublicationCandidateError,
)


def entry(
    *,
    author: str = GOOGLE_AUTHOR_NAME,
    title: str = "Google Threat Intelligence report",
    link: str = "https://cloud.google.com/blog/topics/threat-intelligence/example-report/",
    original_link: str | None = None,
    summary: str = "<p>Safe &amp; bounded summary.</p><script>secret()</script>",
    published_parsed: struct_time | None = struct_time((2026, 7, 15, 8, 30, 0, 2, 196, 0)),
) -> dict[str, object]:
    data: dict[str, object] = {
        "author": author,
        "author_detail": {"name": author},
        "title": title,
        "link": link,
        "summary": summary,
        "published": "Wed, 15 Jul 2026 08:30:00 GMT",
        "published_parsed": published_parsed,
        "updated": "Wed, 15 Jul 2026 09:30:00 GMT",
        "updated_parsed": struct_time((2026, 7, 15, 9, 30, 0, 2, 196, 0)),
        "tags": [{"term": "Threat Research"}],
        "id": "feed-id-1",
    }
    if original_link is not None:
        data["feedburner_origlink"] = original_link
    return data


def test_parse_feed_bytes_returns_bounded_entries() -> None:
    feed = b"""<rss><channel>
<item><title>One</title><link>https://cloud.google.com/blog/topics/threat-intelligence/one/</link></item>
<item><title>Two</title><link>https://cloud.google.com/blog/topics/threat-intelligence/two/</link></item>
</channel></rss>"""

    document = parse_google_threat_feed_entries(feed, max_entries=1)

    assert len(document.entries) == 1
    assert document.entries[0]["title"] == "One"
    assert document.was_truncated is True
    with pytest.raises(GoogleThreatFeedError):
        parse_google_threat_feed_entries("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(GoogleThreatFeedError):
        parse_google_threat_feed_entries(feed, max_entries=MAX_GOOGLE_THREAT_FEED_ENTRIES + 1)


def test_malformed_feed_is_rejected_without_raw_content_disclosure() -> None:
    malformed = b"\xff\xfe\x00SUPER_SECRET_FETCHER_CANARY"

    with pytest.raises(GoogleThreatFeedError) as exc_info:
        parse_google_threat_feed_entries(malformed)

    assert "SUPER_SECRET_FETCHER_CANARY" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("author", "expected_slug"),
    [
        (GOOGLE_AUTHOR_NAME, GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG),
        (MANDIANT_AUTHOR_NAME, MANDIANT_THREAT_RESEARCH_SOURCE_SLUG),
    ],
)
def test_exact_author_routes_to_distinct_source(author: str, expected_slug: str) -> None:
    candidate = adapt_google_threat_publication(entry(author=author))

    assert candidate.source_slug == expected_slug
    assert candidate.canonical_title == "Google Threat Intelligence report"
    assert candidate.summary == "Safe & bounded summary."
    assert candidate.canonical_url == (
        "https://cloud.google.com/blog/topics/threat-intelligence/example-report/"
    )
    assert candidate.source_published_at == datetime(2026, 7, 15, 8, 30, tzinfo=UTC)
    assert candidate.source_modified_at == datetime(2026, 7, 15, 9, 30, tzinfo=UTC)
    assert candidate.safe_source_payload["authoritative_author"] == author
    assert candidate.safe_source_payload["categories"] == ("Threat Research",)
    assert candidate.safe_source_payload["feed_id"] == "feed-id-1"


@pytest.mark.parametrize(
    ("author", "expected_slug"),
    [
        (GOOGLE_AUTHOR_NAME, GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG),
        (MANDIANT_AUTHOR_NAME, MANDIANT_THREAT_RESEARCH_SOURCE_SLUG),
    ],
)
def test_owned_rejection_has_stable_sanitized_diagnostics(
    author: str,
    expected_slug: str,
) -> None:
    private_summary = "PRIVATE_REJECTED_SUMMARY_CANARY"
    rejected = entry(author=author, title=" ", summary=private_summary)

    with pytest.raises(GoogleThreatPublicationRecordError) as first:
        adapt_google_threat_publication(rejected)
    with pytest.raises(GoogleThreatPublicationRecordError) as second:
        adapt_google_threat_publication(rejected)

    assert first.value.source_slug == expected_slug
    assert first.value.failure_stage == "adapter.title_required"
    assert first.value.diagnostic_fingerprint == second.value.diagnostic_fingerprint
    assert len(first.value.diagnostic_fingerprint or "") == 64
    assert set(first.value.diagnostic_fingerprint or "") <= set("0123456789abcdef")
    assert private_summary not in str(first.value)
    assert private_summary not in str(vars(first.value))


def test_distinct_rejected_entries_have_distinct_opaque_fingerprints() -> None:
    first_entry = entry(
        title=" ",
        link="https://cloud.google.com/blog/topics/threat-intelligence/rejected-one/",
    )
    second_entry = entry(
        title=" ",
        link="https://cloud.google.com/blog/topics/threat-intelligence/rejected-two/",
    )

    with pytest.raises(GoogleThreatPublicationRecordError) as first:
        adapt_google_threat_publication(first_entry)
    with pytest.raises(GoogleThreatPublicationRecordError) as second:
        adapt_google_threat_publication(second_entry)

    assert first.value.diagnostic_fingerprint != second.value.diagnostic_fingerprint
    assert "rejected-one" not in str(vars(first.value))
    assert "rejected-two" not in str(vars(second.value))


def test_diagnostic_fingerprint_input_is_bounded_and_fail_closed() -> None:
    private_tail = "PRIVATE_DIAGNOSTIC_TAIL_CANARY"
    rejected = entry(
        title=" ",
        summary=("x" * (MAX_GOOGLE_THREAT_DIAGNOSTIC_BYTES * 2)) + private_tail,
    )

    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(rejected)

    assert exc_info.value.failure_stage == "adapter.title_required"
    assert len(exc_info.value.diagnostic_fingerprint or "") == 64
    assert private_tail not in str(vars(exc_info.value))


def test_diagnostic_metadata_rejects_arbitrary_codes_and_malformed_hashes() -> None:
    error = GoogleThreatPublicationRecordError(
        "fixed safe message",
        source_slug=GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
        failure_stage="PRIVATE_ARBITRARY_VALIDATOR_MESSAGE",
        diagnostic_fingerprint="not-a-valid-fingerprint",
    )

    assert error.failure_stage == "adapter.record_invalid"
    assert error.diagnostic_fingerprint is None


@pytest.mark.parametrize(
    "author_fields",
    [
        {"author": GOOGLE_AUTHOR_NAME},
        {"author_detail": {"name": GOOGLE_AUTHOR_NAME}},
        {"authors": [{"name": GOOGLE_AUTHOR_NAME}]},
        {
            "author": GOOGLE_AUTHOR_NAME,
            "author_detail": {"name": GOOGLE_AUTHOR_NAME},
        },
    ],
    ids=["author-only", "author-detail-only", "authors-only", "matching-fields"],
)
def test_supported_authoritative_author_representations(
    author_fields: dict[str, object],
) -> None:
    data = entry()
    data.pop("author")
    data.pop("author_detail")
    data.update(author_fields)

    candidate = adapt_google_threat_publication(data)

    assert candidate.source_slug == GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG
    assert candidate.safe_source_payload["authoritative_author"] == GOOGLE_AUTHOR_NAME


@pytest.mark.parametrize(
    "author_fields",
    [
        {},
        {"author_detail": GOOGLE_AUTHOR_NAME},
        {"author_detail": {"name": ""}},
        {
            "author": GOOGLE_AUTHOR_NAME,
            "author_detail": {"name": MANDIANT_AUTHOR_NAME},
        },
        {
            "author": GOOGLE_AUTHOR_NAME,
            "authors": [{"name": "Unknown"}],
        },
    ],
    ids=[
        "missing-all",
        "malformed-author-detail",
        "empty-author-detail-name",
        "conflicting-author-detail",
        "unknown-authors-owner",
    ],
)
def test_invalid_authoritative_author_representations_are_rejected(
    author_fields: dict[str, object],
) -> None:
    data = entry()
    data.pop("author")
    data.pop("author_detail")
    data.update(author_fields)

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)


@pytest.mark.parametrize(
    ("author", "expected_slug"),
    [
        (GOOGLE_AUTHOR_NAME, GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG),
        (MANDIANT_AUTHOR_NAME, MANDIANT_THREAT_RESEARCH_SOURCE_SLUG),
    ],
)
def test_late_candidate_error_retains_resolved_source_context(
    monkeypatch: pytest.MonkeyPatch,
    author: str,
    expected_slug: str,
) -> None:
    def fail_normalization(_candidate) -> None:
        raise PublicationCandidateError("private late validation detail")

    monkeypatch.setattr(
        google_threat_publications,
        "normalize_publication_candidate",
        fail_normalization,
    )

    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(author=author))

    assert exc_info.value.source_slug == expected_slug
    assert "private late validation detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    "bad_author",
    ["", "Unknown", "Google", "Google Threat Intelligence Group, Mandiant"],
)
def test_missing_unknown_or_ambiguous_author_is_rejected(bad_author: str) -> None:
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(author=bad_author))


def test_conflicting_author_fields_are_rejected() -> None:
    data = entry(author=GOOGLE_AUTHOR_NAME)
    data["author_detail"] = {"name": MANDIANT_AUTHOR_NAME}

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)


def test_publisher_metadata_does_not_define_or_conflict_with_owner() -> None:
    data = entry(author=GOOGLE_AUTHOR_NAME)
    data["publisher"] = MANDIANT_AUTHOR_NAME
    data["publisher_detail"] = {"name": "Unknown Publisher"}

    candidate = adapt_google_threat_publication(data)

    assert candidate.source_slug == GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG
    data.pop("author")
    data.pop("author_detail")
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)


@pytest.mark.parametrize(
    "updates",
    [
        {"author": ["Google Threat Intelligence Group"]},
        {"author_detail": "Google Threat Intelligence Group"},
        {"author_detail": {"name": ""}},
        {"authors": []},
        {"authors": [{"email": "research@example.com"}]},
        {"authors": [object()]},
        {"author": GOOGLE_AUTHOR_NAME, "authors": [{"name": "Unknown"}]},
        {"author": GOOGLE_AUTHOR_NAME, "authors": [{"name": MANDIANT_AUTHOR_NAME}]},
    ],
)
def test_malformed_or_mixed_author_identity_is_rejected(updates: dict[str, object]) -> None:
    data = entry(author=GOOGLE_AUTHOR_NAME)
    data.update(updates)

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)


def test_feedburner_link_is_not_stored_when_original_cloud_link_is_present() -> None:
    candidate = adapt_google_threat_publication(
        entry(
            link="https://feeds.feedburner.com/threatintelligence/redirect-page",
            original_link=(
                "https://cloud.google.com/blog/topics/threat-intelligence/original/"
                "?utm_source=feed"
            ),
        )
    )

    assert candidate.canonical_url == (
        "https://cloud.google.com/blog/topics/threat-intelligence/original/"
    )


def test_conflicting_authoritative_url_fields_are_rejected() -> None:
    with pytest.raises(GoogleThreatPublicationRecordError, match="conflict"):
        adapt_google_threat_publication(
            entry(
                link="https://cloud.google.com/blog/topics/threat-intelligence/one/",
                original_link="https://cloud.google.com/blog/topics/threat-intelligence/two/",
            )
        )


def test_non_publication_link_rels_are_ignored_without_conflict_or_payload_leak() -> None:
    data = entry(link="https://feeds.feedburner.com/threatintelligence/redirect")
    data["links"] = [
        {
            "rel": "enclosure",
            "href": "https://evil.example/report.pdf?token=secret",
        },
        {
            "rel": "alternate",
            "href": "https://cloud.google.com/blog/topics/threat-intelligence/alternate/",
        },
    ]

    candidate = adapt_google_threat_publication(data)

    assert candidate.canonical_url == (
        "https://cloud.google.com/blog/topics/threat-intelligence/alternate/"
    )
    assert "evil.example" not in str(candidate.safe_source_payload)
    assert "secret" not in str(candidate.safe_source_payload)


@pytest.mark.parametrize(
    "url",
    [
        "https://cloud.google.com/blog/topics/threat-intelligence/",
        "https://www.cloud.google.com/blog/topics/threat-intelligence/post/",
        "https://docs.cloud.google.com/blog/topics/threat-intelligence/post/",
        "https://gtidocs.virustotal.com/blog/topics/threat-intelligence/post/",
        "https://cloud.google.com.evil.example/blog/topics/threat-intelligence/post/",
        "https://evil-cloud.google.com/blog/topics/threat-intelligence/post/",
        "http://cloud.google.com/blog/topics/threat-intelligence/post/",
        "https://user:secret@cloud.google.com/blog/topics/threat-intelligence/post/",
        "https://cloud.google.com:444/blog/topics/threat-intelligence/post/",
        "https://cloud.google.com/security/resources/post/",
        "https://cloud.google.com/blog/topics/threat-intelligence/%65xample/",
        "https://cloud.google.com/blog/topics/threat-intelligence/post;param",
        "https://cloud.google.com/blog/topics/threat-intelligence/post/#fragment",
        "https://cloud.google.com/blog/topics/threat-intelligence/post/?token=secret",
    ],
)
def test_unapproved_urls_are_rejected_without_disclosure(url: str) -> None:
    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(link=url))

    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)


def test_title_required_and_text_controls_are_rejected() -> None:
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(title=" "))
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(title="bad\x00title"))
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(summary="bad\ud800summary"))
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(title="T" * 501))


@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ("Before\tAfter", "Before After"),
        ("Before\nAfter", "Before After"),
        ("Before\rAfter", "Before After"),
        ("Before\t\t\n\n\r\rAfter", "Before After"),
    ],
    ids=["tab", "line-feed", "carriage-return", "mixed-runs"],
)
def test_xml_whitespace_in_summary_is_accepted_and_collapsed(
    summary: str,
    expected: str,
) -> None:
    candidate = adapt_google_threat_publication(entry(summary=summary))

    assert candidate.summary == expected


def test_xml_whitespace_in_title_is_accepted_and_collapsed() -> None:
    candidate = adapt_google_threat_publication(
        entry(title="Google\t\n\rThreat Intelligence report")
    )

    assert candidate.canonical_title == "Google Threat Intelligence report"


@pytest.mark.parametrize(
    "prohibited_character",
    ["\x00", "\x08", "\x0b", "\x0c", "\x1f", "\x7f", "\ud800"],
    ids=[
        "null",
        "backspace",
        "vertical-tab",
        "form-feed",
        "unit-separator",
        "del",
        "surrogate",
    ],
)
def test_prohibited_text_characters_remain_rejected_without_disclosure(
    prohibited_character: str,
) -> None:
    private_source_text = f"private{prohibited_character}source"

    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(summary=private_source_text))

    assert exc_info.type is GoogleThreatPublicationRecordError
    assert private_source_text not in str(exc_info.value)
    assert "private" not in str(exc_info.value).lower()


def test_xml_whitespace_does_not_mask_a_prohibited_control_character() -> None:
    private_source_text = "safe\t\n\rprivate\x0bsource"

    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(summary=private_source_text))

    assert exc_info.type is GoogleThreatPublicationRecordError
    assert private_source_text not in str(exc_info.value)
    assert "private" not in str(exc_info.value).lower()


def test_oversized_normalized_summary_is_truncated_to_shared_limit() -> None:
    normalized_summary = "A" * (MAX_PUBLICATION_SUMMARY_LENGTH + 25)

    candidate = adapt_google_threat_publication(entry(summary=normalized_summary))

    assert candidate.summary == normalized_summary[:MAX_PUBLICATION_SUMMARY_LENGTH]
    assert len(candidate.summary) == MAX_PUBLICATION_SUMMARY_LENGTH


def test_summary_truncation_follows_markup_and_whitespace_normalization() -> None:
    first = "A" * (MAX_PUBLICATION_SUMMARY_LENGTH - 10)
    summary = f"<p>{first}</p>\n\n\t<p>{'B' * 20}</p>"

    candidate = adapt_google_threat_publication(entry(summary=summary))

    assert candidate.summary == first + " " + ("B" * 9)
    assert len(candidate.summary) == MAX_PUBLICATION_SUMMARY_LENGTH
    assert "\n" not in candidate.summary
    assert "\t" not in candidate.summary


def test_malformed_markup_beyond_summary_limit_remains_rejected() -> None:
    summary = "A" * MAX_PUBLICATION_SUMMARY_LENGTH + "Safe <strong"

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(summary=summary))


def test_prohibited_character_beyond_summary_limit_remains_rejected() -> None:
    summary = "A" * MAX_PUBLICATION_SUMMARY_LENGTH + "\x00"

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(summary=summary))


def test_active_markup_beyond_summary_limit_remains_rejected() -> None:
    summary = "A" * MAX_PUBLICATION_SUMMARY_LENGTH + "<script/>discarded"

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(summary=summary))


def test_oversized_title_remains_rejected_without_truncation() -> None:
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(
            entry(title="T" * (MAX_PUBLICATION_TITLE_LENGTH + 1))
        )


def test_summary_precedence_and_description_fallback_remain_unchanged() -> None:
    preferred = entry(summary="Preferred summary")
    preferred["description"] = "Fallback description"
    fallback = entry(summary="  ")
    fallback["description"] = "Fallback description"

    assert adapt_google_threat_publication(preferred).summary == "Preferred summary"
    assert adapt_google_threat_publication(fallback).summary == "Fallback description"


def test_encoded_or_malformed_markup_is_removed_or_rejected_safely() -> None:
    candidate = adapt_google_threat_publication(
        entry(summary="&lt;p&gt;Safe&lt;/p&gt;&lt;script&gt;secret()&lt;/script&gt;")
    )

    assert candidate.summary == "Safe"
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(entry(title="Safe &lt;script"))


@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ("&lt;p&gt;Safe&lt;/p&gt;", "Safe"),
        ("&lt;script&gt;secret()&lt;/script&gt;Safe", "Safe"),
        ("1 < 2", "1 < 2"),
        ("version <= 3", "version <= 3"),
        ("A > B", "A > B"),
        ("Plain text without markup", "Plain text without markup"),
        ("<p><strong>Safe formatting</strong></p>", "Safe formatting"),
    ],
)
def test_plain_text_accepts_complete_markup_and_comparisons(
    summary: str,
    expected: str,
) -> None:
    candidate = adapt_google_threat_publication(entry(summary=summary))

    assert candidate.summary == expected


def test_active_and_non_text_markup_is_removed_completely() -> None:
    candidate = adapt_google_threat_publication(
        entry(
            summary=(
                "Before<!-- comment --><style>.secret{display:none}</style>"
                "<iframe>iframe secret</iframe><object>object secret</object>"
                '<embed src="secret"/><svg><text>svg secret</text></svg>'
                "<math><mi>math secret</mi></math><?feed safe?>"
                "<!DOCTYPE html>After"
            )
        )
    )

    assert candidate.summary == "Before After"
    assert "secret" not in candidate.summary


@pytest.mark.parametrize(
    "summary",
    [
        "<script/>secret()",
        "<script />secret()",
        "<SCRIPT/>secret()",
        "<script / >secret()",
        '<script src="x"/>token=secret',
        "<style/>body{display:none}",
        '<style type="text/css"/>password=secret',
        "<iframe/>fallback secret",
        "<iframe sandbox/>fallback secret",
        "<object/>fallback secret",
        '<object data="secret"/>fallback secret',
        "&lt;script/&gt;secret()",
        "&lt;style/&gt;body{display:none}",
        "&lt;iframe/&gt;fallback secret",
        "&lt;object/&gt;fallback secret",
        "&amp;lt;script/&amp;gt;secret()",
        "&amp;amp;lt;style/&amp;amp;gt;body{display:none}",
    ],
)
def test_self_closing_non_void_active_containers_are_rejected_without_disclosure(
    summary: str,
) -> None:
    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(summary=summary))

    message = str(exc_info.value)
    assert summary not in message
    assert "secret" not in message.lower()
    assert "token" not in message.lower()
    assert "password" not in message.lower()


@pytest.mark.parametrize(
    "summary",
    [
        "<script>secret()</script>Safe",
        "<style>body{display:none}</style>Safe",
        "<iframe>fallback secret</iframe>Safe",
        "<object>fallback secret</object>Safe",
        "<iframe><object>nested secret</object></iframe>Safe",
    ],
)
def test_paired_active_containers_are_removed_safely(summary: str) -> None:
    candidate = adapt_google_threat_publication(entry(summary=summary))

    assert candidate.summary == "Safe"


@pytest.mark.parametrize(
    "summary",
    [
        "Before<br/>After",
        "Before<hr />After",
        'Before<embed src="ignored"/>After',
        "Before<svg/>After",
        "Before<math/>After",
    ],
)
def test_safe_self_closing_markup_behavior_is_preserved(summary: str) -> None:
    candidate = adapt_google_threat_publication(entry(summary=summary))

    assert candidate.summary == "Before After"


@pytest.mark.parametrize(
    "malformed_text",
    [
        "Safe &lt;script",
        "Safe &lt;/script",
        "Safe &lt;p",
        "Safe &lt;div class=&quot;x&quot;",
        "Safe <script",
        "Safe </script",
        "Safe <p",
        'Safe <div class="x"',
        "Safe &amp;lt;script",
        "Safe &amp;amp;lt;div class=&amp;quot;x&amp;quot;",
        "Safe <script>api_key=super-secret",
        'Safe <iframe src="token=super-secret"',
        "Safe <!-- token=super-secret",
        "Safe <!DOCTYPE token=super-secret",
        "Safe <?target token=super-secret",
        "Safe text then <strong data-token='super-secret'",
    ],
)
def test_malformed_markup_is_rejected_without_disclosure(
    malformed_text: str,
) -> None:
    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(entry(title=malformed_text))

    message = str(exc_info.value)
    assert malformed_text not in message
    assert "secret" not in message.lower()
    assert "token" not in message.lower()


def test_summary_uses_only_summary_or_description_not_feed_content() -> None:
    data = entry(summary="")
    data["description"] = ""
    data["content"] = [{"value": "<p>Article body must not be stored.</p>"}]

    candidate = adapt_google_threat_publication(data)

    assert candidate.summary is None
    assert "Article body" not in str(candidate.safe_source_payload)


@pytest.mark.parametrize(
    "field_update",
    [
        {"author": GOOGLE_AUTHOR_NAME + ("x" * 201)},
        {"tags": [{"term": "c" * 101}]},
        {"id": "f" * 301},
    ],
)
def test_overlong_identity_metadata_is_rejected(field_update: dict[str, object]) -> None:
    data = entry(author=GOOGLE_AUTHOR_NAME)
    data.update(field_update)

    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)



def test_unicode_is_preserved_and_metadata_lists_are_bounded() -> None:
    data = entry(title="تحليل أمني", summary="ملخص آمن")
    data["tags"] = [{"term": f"tag-{index}"} for index in range(MAX_GOOGLE_THREAT_CATEGORIES)]

    candidate = adapt_google_threat_publication(data)

    assert candidate.canonical_title == "تحليل أمني"
    assert candidate.summary == "ملخص آمن"
    assert len(candidate.safe_source_payload["categories"]) == MAX_GOOGLE_THREAT_CATEGORIES
    data["tags"] = [{"term": f"tag-{index}"} for index in range(MAX_GOOGLE_THREAT_CATEGORIES + 1)]
    with pytest.raises(GoogleThreatPublicationRecordError):
        adapt_google_threat_publication(data)


def test_invalid_per_record_timestamp_is_contained_safely() -> None:
    raw_date = "0000-01-01T00:00:00Z"
    data = entry()
    data["published"] = raw_date
    data["published_parsed"] = struct_time((0, 1, 1, 0, 0, 0, 0, 1, 0))

    with pytest.raises(GoogleThreatPublicationRecordError) as exc_info:
        adapt_google_threat_publication(data)

    assert raw_date not in str(exc_info.value)


def test_external_id_is_stable_and_source_separated() -> None:
    canonical_url = "https://cloud.google.com/blog/topics/threat-intelligence/example/"
    google_id = derive_google_threat_external_id(
        GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
        canonical_url,
    )
    mandiant_id = derive_google_threat_external_id(
        MANDIANT_THREAT_RESEARCH_SOURCE_SLUG,
        canonical_url,
    )

    assert google_id != mandiant_id
    assert google_id == derive_google_threat_external_id(
        GOOGLE_THREAT_INTELLIGENCE_SOURCE_SLUG,
        canonical_url,
    )
    assert google_id.endswith(google_id.rsplit(":", 1)[1])
    assert len(google_id.rsplit(":", 1)[1]) == 64
