from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
import socket
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import operators

from app.ingestion.normalizers.rss import normalize_rss_feed
from app.ingestion import publication_pipeline
from app.ingestion.adapters.censys_publications import (
    CENSYS_ARC_RESEARCH_SLUG,
    CENSYS_RAPID_RESPONSE_SLUG,
    adapt_censys_publication,
)
from app.ingestion.publication_pipeline import (
    MAX_PUBLICATION_EXTERNAL_ID_LENGTH,
    MAX_PUBLICATION_TITLE_LENGTH,
    MAX_PUBLICATION_URL_LENGTH,
    MAX_SAFE_PAYLOAD_KEYS,
    MAX_SAFE_PAYLOAD_SEQUENCE_ITEMS,
    MAX_SAFE_PAYLOAD_BYTES,
    PublicationCandidate,
    PublicationCandidateError,
    PublicationPersistenceError,
    PublicationPipeline,
    PublicationSourceError,
    canonicalize_publication_url,
    normalize_publication_candidate,
    publication_item_type_for_content_family,
    safe_publication_external_id_for_error,
)
from app.ingestion.source_registry import (
    AccessMethod,
    ContentFamily,
    ImplementationStatus,
    SourceDefinition,
)
from app.ingestion.services.article_identity_service import (
    ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
    ARTICLE_URL_IDENTIFIER_NAMESPACE,
)
from app.ingestion.services.rss_ingestion_service import RssIngestionService
from app.models import (
    IntelligenceItem,
    IntelligenceItemIdentifier,
    IntelligenceSource,
    SourceRecord,
)


OBSERVED_AT = datetime(2026, 7, 10, 8, 0, tzinfo=UTC)
RSS_SOURCE_SLUG = "cert-eu-security-advisories"
THREAT_SOURCE_SLUG = "test-threat-research"
SECOND_THREAT_SOURCE_SLUG = "test-threat-research-secondary"
THREAT_SOURCE_HOST = "research.example.com"


class ScalarResult:
    def __init__(self, value: object | None):
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class FakeSession:
    def __init__(self, *, fail_flush: bool = False):
        self.fail_flush = fail_flush
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.sources: list[IntelligenceSource] = []
        self.items: list[IntelligenceItem] = []
        self.source_records: list[SourceRecord] = []
        self.identifiers: list[IntelligenceItemIdentifier] = []

    def add(self, record: object) -> None:
        if isinstance(record, IntelligenceSource):
            collection = self.sources
        elif isinstance(record, IntelligenceItem):
            collection = self.items
        elif isinstance(record, SourceRecord):
            collection = self.source_records
        elif isinstance(record, IntelligenceItemIdentifier):
            collection = self.identifiers
        else:
            raise AssertionError(f"Unexpected record type: {type(record)}")
        if record not in collection:
            collection.append(record)

    def flush(self) -> None:
        if self.fail_flush:
            raise SQLAlchemyError("postgresql://private-user:private-password@host/db")
        self.flushes += 1
        for collection in (self.sources, self.items, self.source_records, self.identifiers):
            for index, record in enumerate(collection, start=1):
                if getattr(record, "id", None) is None:
                    record.id = index
                if isinstance(record, SourceRecord):
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.intelligence_item is not None:
                        record.intelligence_item_id = record.intelligence_item.id
                if isinstance(record, IntelligenceItemIdentifier):
                    if record.intelligence_item is not None:
                        record.intelligence_item_id = record.intelligence_item.id
                    if record.source is not None:
                        record.source_id = record.source.id
                    if record.source_record is not None:
                        record.source_record_id = record.source_record.id

    def execute(self, statement: Any) -> ScalarResult:
        entity = statement.column_descriptions[0]["entity"]
        criteria = list(statement._where_criteria)
        if entity is IntelligenceSource:
            slug = criterion_value(criteria, "slug")
            return ScalarResult(
                next((source for source in self.sources if source.slug == slug), None)
            )
        if entity is SourceRecord:
            source_id = criterion_value(criteria, "source_id")
            external_id = criterion_value(criteria, "source_external_id")
            url_hash = criterion_value(criteria, "canonical_url_hash")
            return ScalarResult(
                next(
                    (
                        record
                        for record in self.source_records
                        if record.source_id == source_id
                        and (
                            (
                                external_id is not None
                                and record.source_external_id == external_id
                            )
                            or (
                                url_hash is not None
                                and record.canonical_url_hash == url_hash
                            )
                        )
                    ),
                    None,
                )
            )
        if entity is IntelligenceItemIdentifier:
            namespace = criterion_value(criteria, "namespace")
            normalized_value = criterion_value(criteria, "normalized_value")
            source_is_null = any(
                getattr(getattr(criterion, "left", None), "name", None) == "source_id"
                and getattr(criterion, "operator", None) is operators.is_
                for criterion in criteria
            )
            matches = [
                identifier
                for identifier in self.identifiers
                if (not source_is_null or identifier.source_id is None)
                and identifier.namespace == namespace
                and identifier.normalized_value == normalized_value
            ]
            if len(matches) > 1:
                raise AssertionError("Ambiguous identifier query in fake session.")
            return ScalarResult(matches[0] if matches else None)
        raise AssertionError(f"Unexpected select entity: {entity}")

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def criterion_value(criteria: list[object], column_name: str) -> object:
    for criterion in criteria:
        left = getattr(criterion, "left", None)
        if getattr(left, "name", None) != column_name:
            continue
        right = getattr(criterion, "right", None)
        if hasattr(right, "value"):
            return right.value
    return None


def candidate(
    *,
    source_slug: str = RSS_SOURCE_SLUG,
    source_external_id: str = "CERT-EU-SA2026-001",
    title: str = "CERT-EU Security Advisory",
    url: str = "https://cert.europa.eu/publications/security-advisories/2026-001",
    summary: str | None = "Safe advisory summary.",
    published_at: object = datetime(2026, 7, 8, 8, 30, tzinfo=UTC),
    modified_at: object | None = None,
    payload: dict[str, object] | None = None,
) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=source_slug,
        source_external_id=source_external_id,
        canonical_title=title,
        canonical_url=url,
        summary=summary,
        source_published_at=published_at,  # type: ignore[arg-type]
        source_modified_at=modified_at,  # type: ignore[arg-type]
        safe_source_payload=(
            {"source_id": source_external_id} if payload is None else payload
        ),
    )


def threat_source(slug: str = THREAT_SOURCE_SLUG) -> SourceDefinition:
    return SourceDefinition(
        slug=slug,
        display_name=f"Test Threat Research {slug}",
        vendor="Test",
        source_family="Threat research",
        content_family=ContentFamily.THREAT_RESEARCH,
        access_method=AccessMethod.PUBLIC_PUBLICATION,
        allowed_hosts=(THREAT_SOURCE_HOST,),
        authentication_required=False,
        structured=False,
        implementation_status=ImplementationStatus.IMPLEMENTED,
        enabled=True,
        source_type="rss",
        base_url=f"https://{THREAT_SOURCE_HOST}/feed/{slug}",
        rate_limit_notes="Offline test source only.",
    )


def install_threat_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    sources = {
        THREAT_SOURCE_SLUG: threat_source(),
        SECOND_THREAT_SOURCE_SLUG: threat_source(SECOND_THREAT_SOURCE_SLUG),
    }
    original_get_source_definition = publication_pipeline.get_source_definition
    original_source_allows_publication_hostname = (
        publication_pipeline.source_allows_publication_hostname
    )

    def fake_get_source_definition(slug: str):
        if slug in sources:
            return sources[slug]
        return original_get_source_definition(slug)

    def fake_source_allows_publication_hostname(slug: str, hostname: str) -> bool:
        if slug in sources:
            return hostname.rstrip(".").lower() == THREAT_SOURCE_HOST
        return original_source_allows_publication_hostname(slug, hostname)

    monkeypatch.setattr(publication_pipeline, "get_source_definition", fake_get_source_definition)
    monkeypatch.setattr(
        publication_pipeline,
        "source_allows_publication_hostname",
        fake_source_allows_publication_hostname,
    )


def threat_candidate(
    *,
    source_slug: str = THREAT_SOURCE_SLUG,
    source_external_id: str = "report-001",
    title: str = "Threat Research Report",
    url: str = f"https://{THREAT_SOURCE_HOST}/reports/001",
    summary: str | None = "Threat research summary.",
    published_at: object = datetime(2026, 7, 8, 8, 30, tzinfo=UTC),
    modified_at: object | None = None,
) -> PublicationCandidate:
    return PublicationCandidate(
        source_slug=source_slug,
        source_external_id=source_external_id,
        canonical_title=title,
        canonical_url=url,
        summary=summary,
        source_published_at=published_at,  # type: ignore[arg-type]
        source_modified_at=modified_at,  # type: ignore[arg-type]
        safe_source_payload={"source_id": source_external_id},
    )


def add_existing_item_with_fingerprints(
    session: FakeSession,
    *,
    item_type: str,
    url_hash: str,
    title_hash: str,
) -> IntelligenceItem:
    source = IntelligenceSource(
        slug=f"existing-{item_type}",
        name=f"Existing {item_type}",
        source_type="rss",
        base_url="https://example.com/feed",
        is_enabled=True,
    )
    item = IntelligenceItem(
        item_type=item_type,
        canonical_title="Existing publication",
        canonical_url="https://example.com/publication",
        collected_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        status="active",
        geographic_scope="global",
        uae_relevance_status="unknown",
        uae_relevance_method="unassigned",
        analyst_review_status="pending",
    )
    source_record = SourceRecord(
        source=source,
        intelligence_item=item,
        source_external_id=f"existing-{item_type}",
        source_url="https://example.com/publication",
        canonical_url_hash=url_hash,
        content_hash="0" * 64,
        is_primary_reference=True,
        payload_collected_at=OBSERVED_AT,
        first_seen_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
        processing_status="processed",
        upstream_status="present",
    )
    session.add(source)
    session.add(item)
    session.add(source_record)
    session.add(
        IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=ARTICLE_URL_IDENTIFIER_NAMESPACE,
            identifier_value=url_hash,
            normalized_value=url_hash,
            is_primary=False,
        )
    )
    session.add(
        IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=ARTICLE_TITLE_IDENTIFIER_NAMESPACE,
            identifier_value=title_hash,
            normalized_value=title_hash,
            is_primary=False,
        )
    )
    session.flush()
    return item


def test_publication_url_canonicalization_preserves_safe_query_and_strips_tracking() -> None:
    url = (
        "https://cert.europa.eu./publications/security-advisories/2026-001"
        "?b=2&utm_source=x&a=1#g"
    )

    assert canonicalize_publication_url(RSS_SOURCE_SLUG, url) == (
        "https://cert.europa.eu/publications/security-advisories/2026-001?a=1&b=2"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://cert.europa.eu/path?api_key=secret",
        "https://cert.europa.eu/path?API-KEY=secret",
        "https://cert.europa.eu/path?access_token=secret",
        "https://cert.europa.eu/path?token=secret",
        "https://cert.europa.eu/path?signature=secret",
        "https://cert.europa.eu/path?x-amz-signature=secret",
        "https://cert.europa.eu/path?x-amz-credential=secret",
        "https://cert.europa.eu/path?x-amz-security-token=secret",
        "https://cert.europa.eu/path?x-goog-signature=secret",
        "https://cert.europa.eu/path?x-goog-credential=secret",
        "https://cert.europa.eu/path?x-goog-security-token=secret",
        "https://cert.europa.eu/path?password=",
    ],
)
def test_sensitive_publication_query_parameters_are_rejected_safely(url: str) -> None:
    with pytest.raises(PublicationCandidateError) as exc_info:
        canonicalize_publication_url(RSS_SOURCE_SLUG, url)

    assert url not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)
    assert "api" not in str(exc_info.value).lower()


def test_safe_query_parameters_remain_preserved_and_tracking_is_removed() -> None:
    assert canonicalize_publication_url(
        RSS_SOURCE_SLUG,
        "https://cert.europa.eu/path?b=2&utm_source=x&a=1",
    ) == "https://cert.europa.eu/path?a=1&b=2"


@pytest.mark.parametrize(
    "key",
    [
        "sig",
        "CLIENT-SECRET",
        "auth.token",
        "ID_TOKEN",
        "session-token",
        "sas.token",
        "bearer_token",
        "X-API-KEY",
        "\uff38\uff3f\uff21\uff30\uff29\uff3f\uff2b\uff25\uff39",
        "secret.key",
        "token",
        "API_TOKEN",
        "api.token.value",
        "OAuth_Token",
        "oauth2-token",
        "jwt",
        "JWT_TOKEN",
        "PRIVATE-KEY",
        "access.key",
        "SECRET_ACCESS_KEY",
        "AWSAccessKeyId",
        "aws_access_key_id",
        "google-access-id",
    ],
)
def test_sensitive_query_aliases_are_rejected_without_disclosure(key: str) -> None:
    url = f"https://cert.europa.eu/path?{key}=credential-value"

    with pytest.raises(PublicationCandidateError) as exc_info:
        canonicalize_publication_url(RSS_SOURCE_SLUG, url)

    message = str(exc_info.value)
    assert key not in message
    assert "credential-value" not in message
    assert url not in message


def test_similar_noncredential_query_keys_remain_allowed() -> None:
    assert canonicalize_publication_url(
        RSS_SOURCE_SLUG,
        (
            "https://cert.europa.eu/path?tokenization=mode&signal=on"
            "&signature_version=4&private_key_algorithm=RSA"
            "&client_id=public-id&client_identifier=public"
            "&accessibility=enabled"
        ),
    ) == (
        "https://cert.europa.eu/path?accessibility=enabled"
        "&client_id=public-id&client_identifier=public"
        "&private_key_algorithm=RSA&signal=on"
        "&signature_version=4&tokenization=mode"
    )


@pytest.mark.parametrize(
    "source_slug",
    [
        "nvd",
        "cisa-kev",
        "missing-source",
    ],
)
def test_non_publication_or_unimplemented_sources_fail_closed(source_slug: str) -> None:
    with pytest.raises(PublicationSourceError):
        normalize_publication_candidate(candidate(source_slug=source_slug))


def test_google_threat_publication_source_rejects_wrong_publication_host() -> None:
    with pytest.raises(PublicationCandidateError, match="host"):
        normalize_publication_candidate(
            candidate(source_slug="google-threat-intelligence-public-research")
        )


def censys_record(
    *,
    title: str = "Censys ARC Research",
    url: str = "https://censys.com/blog/arc-research/",
    summary: str = "Safe public research summary.",
) -> dict[str, object]:
    return {
        "title": title,
        "url": url,
        "summary": summary,
        "published_at": "2026-07-01T12:00:00Z",
        "modified_at": None,
        "authors": ["Censys Research"],
        "categories": ["Research"],
    }


@pytest.mark.parametrize(
    ("source_slug", "url", "expected_item_type"),
    [
        (
            CENSYS_ARC_RESEARCH_SLUG,
            "https://censys.com/blog/arc-research/",
            "threat_report",
        ),
        (
            CENSYS_RAPID_RESPONSE_SLUG,
            "https://censys.com/advisory/cve-example/",
            "security_advisory",
        ),
    ],
)
def test_censys_candidates_create_registry_derived_item_types(
    source_slug: str,
    url: str,
    expected_item_type: str,
) -> None:
    session = FakeSession()
    pipeline = PublicationPipeline(session)

    result = pipeline.persist(
        adapt_censys_publication(source_slug, censys_record(url=url)),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "created"
    assert session.items[0].item_type == expected_item_type
    assert session.commits == 0
    assert session.rollbacks == 0


def test_censys_repeated_import_is_unchanged_then_safe_change_updates() -> None:
    session = FakeSession()
    pipeline = PublicationPipeline(session)
    original = adapt_censys_publication(CENSYS_ARC_RESEARCH_SLUG, censys_record())

    assert pipeline.persist(original, observed_at=OBSERVED_AT).outcome == "created"
    assert pipeline.persist(original, observed_at=OBSERVED_AT).outcome == "unchanged"
    updated = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        censys_record(summary="Updated safe public research summary."),
    )
    assert pipeline.persist(updated, observed_at=OBSERVED_AT).outcome == "updated"
    assert session.commits == 0
    assert session.rollbacks == 0


def test_censys_cross_type_title_identity_fails_safely() -> None:
    session = FakeSession()
    pipeline = PublicationPipeline(session)
    title = "Shared Censys Publication Title"

    research = adapt_censys_publication(
        CENSYS_ARC_RESEARCH_SLUG,
        censys_record(title=title),
    )
    advisory = adapt_censys_publication(
        CENSYS_RAPID_RESPONSE_SLUG,
        censys_record(
            title=title,
            url="https://censys.com/advisory/cve-example/",
        ),
    )

    assert pipeline.persist(research, observed_at=OBSERVED_AT).outcome == "created"
    result = pipeline.persist(advisory, observed_at=OBSERVED_AT)

    assert result.outcome == "failed"
    assert "identity signals conflict" in (result.message or "")
    assert len(session.items) == 1
    assert session.commits == 0
    assert session.rollbacks == 0


def test_pipeline_does_not_expose_normalized_persistence_bypass() -> None:
    assert not hasattr(PublicationPipeline(FakeSession()), "persist_normalized")


def test_unregistered_source_slug_cannot_create_source_row() -> None:
    session = FakeSession()

    result = PublicationPipeline(session).persist(
        candidate(source_slug="not-registered"),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "failed"
    assert "registered" in (result.message or "")
    assert session.sources == []


def test_forged_url_cannot_bypass_registry_host_validation() -> None:
    session = FakeSession()

    result = PublicationPipeline(session).persist(
        candidate(url="https://example.com/publications/security-advisories/2026-001"),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "failed"
    assert "host" in (result.message or "")
    assert session.sources == []
    assert session.items == []


@pytest.mark.parametrize(
    ("content_family", "expected"),
    [
        (ContentFamily.SECURITY_ADVISORY, "security_advisory"),
        (ContentFamily.PUBLIC_OSINT_ADVISORY, "security_advisory"),
        (ContentFamily.THREAT_RESEARCH, "threat_report"),
        (ContentFamily.EXPOSURE_RESEARCH, "threat_report"),
    ],
)
def test_publication_item_type_is_derived_from_content_family(
    content_family: ContentFamily,
    expected: str,
) -> None:
    assert publication_item_type_for_content_family(content_family) == expected


def test_unsupported_content_family_mapping_fails_safely() -> None:
    with pytest.raises(PublicationSourceError):
        publication_item_type_for_content_family(ContentFamily.VULNERABILITY)


def test_threat_report_candidate_is_idempotent_and_updates(monkeypatch: pytest.MonkeyPatch) -> None:
    install_threat_sources(monkeypatch)
    session = FakeSession()
    pipeline = PublicationPipeline(session)
    record = threat_candidate()

    first = pipeline.persist(record, observed_at=OBSERVED_AT)
    second = pipeline.persist(record, observed_at=OBSERVED_AT + timedelta(hours=1))
    updated = pipeline.persist(
        threat_candidate(summary="Updated threat research summary."),
        observed_at=OBSERVED_AT + timedelta(hours=2),
    )

    assert first.outcome == "created"
    assert second.outcome == "unchanged"
    assert updated.outcome == "updated"
    assert len(session.items) == 1
    assert session.items[0].item_type == "threat_report"
    assert session.items[0].summary == "Updated threat research summary."


def test_two_threat_sources_can_link_same_report(monkeypatch: pytest.MonkeyPatch) -> None:
    install_threat_sources(monkeypatch)
    session = FakeSession()
    pipeline = PublicationPipeline(session)

    first = pipeline.persist(threat_candidate(), observed_at=OBSERVED_AT)
    second = pipeline.persist(
        threat_candidate(
            source_slug=SECOND_THREAT_SOURCE_SLUG,
            source_external_id="report-001-secondary",
        ),
        observed_at=OBSERVED_AT,
    )

    assert first.outcome == "created"
    assert second.outcome == "created"
    assert second.message == "A new source record was linked to an existing publication."
    assert len(session.items) == 1
    assert len(session.source_records) == 2
    assert all(record.intelligence_item is session.items[0] for record in session.source_records)
    assert session.items[0].item_type == "threat_report"


def test_threat_report_cannot_link_to_existing_security_advisory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_threat_sources(monkeypatch)
    session = FakeSession()
    normalized = normalize_publication_candidate(threat_candidate())
    add_existing_item_with_fingerprints(
        session,
        item_type="security_advisory",
        url_hash=normalized.canonical_url_hash,
        title_hash=normalized.normalized_title_hash,
    )

    result = PublicationPipeline(session).persist(threat_candidate(), observed_at=OBSERVED_AT)

    assert result.outcome == "failed"
    assert "publication identity signals conflict" in (result.message or "")
    assert len(session.items) == 1


def test_security_advisory_cannot_link_to_existing_threat_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_threat_sources(monkeypatch)
    session = FakeSession()
    advisory = candidate(
        title="Shared Report",
        url="https://cert.europa.eu/publications/shared-report",
    )
    normalized = normalize_publication_candidate(advisory)
    add_existing_item_with_fingerprints(
        session,
        item_type="threat_report",
        url_hash=normalized.canonical_url_hash,
        title_hash=normalized.normalized_title_hash,
    )

    result = PublicationPipeline(session).persist(advisory, observed_at=OBSERVED_AT)

    assert result.outcome == "failed"
    assert "advisory identity signals conflict" in (result.message or "")
    assert len(session.items) == 1


@pytest.mark.parametrize(
    "namespace",
    [ARTICLE_URL_IDENTIFIER_NAMESPACE, ARTICLE_TITLE_IDENTIFIER_NAMESPACE],
)
def test_threat_report_duplicate_local_identifiers_use_publication_wording(
    monkeypatch: pytest.MonkeyPatch,
    namespace: str,
) -> None:
    install_threat_sources(monkeypatch)
    session = FakeSession()
    pipeline = PublicationPipeline(session)
    first = pipeline.persist(threat_candidate(), observed_at=OBSERVED_AT)
    item = session.items[0]
    original_summary = item.summary
    session.add(
        IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=namespace,
            identifier_value="f" * 64,
            normalized_value="f" * 64,
            is_primary=False,
        )
    )
    session.flush()

    result = pipeline.persist(
        threat_candidate(summary="Changed threat research summary."),
        observed_at=OBSERVED_AT + timedelta(hours=1),
    )

    assert first.outcome == "created"
    assert result.outcome == "failed"
    assert result.message == "The publication identity signals conflict with existing records."
    assert "RSS" not in result.message
    assert "advisory" not in result.message.lower()
    assert item.item_type == "threat_report"
    assert item.summary == original_summary
    assert len(session.items) == 1


@pytest.mark.parametrize(
    "namespace",
    [ARTICLE_URL_IDENTIFIER_NAMESPACE, ARTICLE_TITLE_IDENTIFIER_NAMESPACE],
)
def test_advisory_duplicate_local_identifiers_preserve_advisory_wording(
    namespace: str,
) -> None:
    session = FakeSession()
    pipeline = PublicationPipeline(session)
    first = pipeline.persist(candidate(), observed_at=OBSERVED_AT)
    item = session.items[0]
    original_summary = item.summary
    session.add(
        IntelligenceItemIdentifier(
            intelligence_item=item,
            source=None,
            source_record=None,
            namespace=namespace,
            identifier_value="f" * 64,
            normalized_value="f" * 64,
            is_primary=False,
        )
    )
    session.flush()

    result = pipeline.persist(
        candidate(summary="Changed advisory summary."),
        observed_at=OBSERVED_AT + timedelta(hours=1),
    )

    assert first.outcome == "created"
    assert result.outcome == "failed"
    assert result.message == "The advisory identity signals conflict with existing records."
    assert item.item_type == "security_advisory"
    assert item.summary == original_summary
    assert len(session.items) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://cert.europa.eu/publications/x",
        "https://example.com/publications/x",
        "https://evil.cert.europa.eu/publications/x",
        "https://cert.europa.eu.evil.example/publications/x",
        "https://user:pass@cert.europa.eu/publications/x",
        "https://cert.europa.eu../publications/x",
        "https://cert.europa.eu:444/publications/x",
        "https://cert.europa.eu:bad/feed",
    ],
)
def test_publication_url_boundary_rejections_are_sanitized(url: str) -> None:
    with pytest.raises(PublicationCandidateError) as exc_info:
        canonicalize_publication_url(RSS_SOURCE_SLUG, url)

    assert url not in str(exc_info.value)


@pytest.mark.parametrize("control", ["\x00", "\r", "\n", "\t", "\x1f", "\x7f", "\ud800"])
def test_raw_url_controls_and_surrogates_fail_before_parsing(control: str) -> None:
    url = f"https://cert.europa.eu/publications/secur{control}ity-advisory"

    with pytest.raises(PublicationCandidateError) as exc_info:
        canonicalize_publication_url(RSS_SOURCE_SLUG, url)

    message = str(exc_info.value)
    assert url not in message
    assert control not in message
    assert "Unicode" not in message


def test_candidate_validation_rejects_naive_dates_and_nested_payloads() -> None:
    naive = candidate(published_at=datetime(2026, 7, 8, 8, 30))

    with pytest.raises(PublicationCandidateError, match="timezone-aware"):
        normalize_publication_candidate(naive)
    with pytest.raises(PublicationCandidateError, match="unsafe"):
        candidate(payload={"source_id": "CERT-EU-SA2026-001", "raw": {"html": "<b>x</b>"}})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("source_published_at", "2026-07-01T00:00:00Z"),
        ("source_modified_at", 123),
    ],
)
def test_malformed_timestamps_fail_safely(field_name: str, value: object) -> None:
    kwargs = {"published_at": OBSERVED_AT, "modified_at": None}
    if field_name == "source_published_at":
        kwargs["published_at"] = value
    else:
        kwargs["modified_at"] = value

    with pytest.raises(PublicationCandidateError) as exc_info:
        normalize_publication_candidate(candidate(**kwargs))  # type: ignore[arg-type]

    assert "AttributeError" not in str(exc_info.value)
    assert "TypeError" not in str(exc_info.value)
    assert str(value) not in str(exc_info.value)


def test_aware_publication_timestamps_normalize_to_utc_and_stable_hashes() -> None:
    first = normalize_publication_candidate(
        candidate(published_at=datetime(2026, 7, 8, 12, 30, tzinfo=timezone(timedelta(hours=4))))
    )
    second = normalize_publication_candidate(
        candidate(published_at=datetime(2026, 7, 8, 8, 30, tzinfo=UTC))
    )

    assert first.source_published_at == datetime(2026, 7, 8, 8, 30, tzinfo=UTC)
    assert second.source_published_at == datetime(2026, 7, 8, 8, 30, tzinfo=UTC)
    assert first.content_hash == second.content_hash


class RaisingTimezone(tzinfo):
    def utcoffset(self, dt):  # type: ignore[no-untyped-def]
        raise RuntimeError("secret timestamp failure")

    def dst(self, dt):  # type: ignore[no-untyped-def]
        return None


def test_bad_tzinfo_failure_is_sanitized() -> None:
    bad_timestamp = datetime(2026, 7, 8, 8, 30, tzinfo=RaisingTimezone())

    with pytest.raises(PublicationCandidateError) as exc_info:
        normalize_publication_candidate(candidate(published_at=bad_timestamp))

    assert "secret" not in str(exc_info.value)
    assert "RuntimeError" not in str(exc_info.value)


@pytest.mark.parametrize("marker", ["2026-07-01", 0])
def test_malformed_observed_at_returns_sanitized_failed_result(marker: object) -> None:

    result = PublicationPipeline(FakeSession()).persist(
        candidate(),
        observed_at=marker,  # type: ignore[arg-type]
    )

    assert result.outcome == "failed"
    assert str(marker) not in (result.message or "")
    assert "AttributeError" not in (result.message or "")


def test_required_identity_fields_reject_oversized_values_without_truncation() -> None:
    exact_id = "I" * MAX_PUBLICATION_EXTERNAL_ID_LENGTH
    exact_title = "T" * MAX_PUBLICATION_TITLE_LENGTH
    normalized = normalize_publication_candidate(
        candidate(source_external_id=exact_id, title=exact_title)
    )

    assert normalized.source_external_id == exact_id
    assert normalized.canonical_title == exact_title
    with pytest.raises(PublicationCandidateError):
        normalize_publication_candidate(
            candidate(source_external_id="I" * (MAX_PUBLICATION_EXTERNAL_ID_LENGTH + 1))
        )
    with pytest.raises(PublicationCandidateError):
        normalize_publication_candidate(
            candidate(title="T" * (MAX_PUBLICATION_TITLE_LENGTH + 1))
        )


def test_oversized_ids_do_not_collapse_to_same_normalized_identity() -> None:
    first = "A" * MAX_PUBLICATION_EXTERNAL_ID_LENGTH + "1"
    second = "A" * MAX_PUBLICATION_EXTERNAL_ID_LENGTH + "2"

    with pytest.raises(PublicationCandidateError):
        normalize_publication_candidate(candidate(source_external_id=first))
    with pytest.raises(PublicationCandidateError):
        normalize_publication_candidate(candidate(source_external_id=second))


@pytest.mark.parametrize(
    ("candidate_kwargs", "rejected_value"),
    [
        (
            {
                "source_external_id": "unsafe\x00external-id",
                "payload": {"source_id": "safe-id"},
            },
            "unsafe\x00external-id",
        ),
        ({"title": "unsafe\x00title"}, "unsafe\x00title"),
        ({"summary": "unsafe\x00summary"}, "unsafe\x00summary"),
        ({"title": "unsafe\ud800title"}, "unsafe\ud800title"),
    ],
)
def test_database_unsafe_publication_text_fails_safely(
    candidate_kwargs: dict[str, object],
    rejected_value: str,
) -> None:
    with pytest.raises(PublicationCandidateError) as exc_info:
        normalize_publication_candidate(candidate(**candidate_kwargs))  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert rejected_value not in message
    assert "Unicode" not in message


def test_unsafe_external_id_is_not_returned_in_failed_result() -> None:
    record = candidate(
        source_external_id="unsafe\x00external-id",
        payload={"source_id": "safe-id"},
    )

    result = PublicationPipeline(FakeSession()).persist(record, observed_at=OBSERVED_AT)

    assert result.outcome == "failed"
    assert result.source_external_id == "unknown"
    assert "unsafe" not in (result.message or "")
    assert "\x00" not in (result.message or "")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CERT-EU-SA2026-001", "CERT-EU-SA2026-001"),
        ("A" * (MAX_PUBLICATION_EXTERNAL_ID_LENGTH + 1), "A" * MAX_PUBLICATION_EXTERNAL_ID_LENGTH),
        ("", "unknown"),
        ("unsafe\x00id", "unknown"),
        ("unsafe\nid", "unknown"),
        ("unsafe\ud800id", "unknown"),
        (None, "unknown"),
    ],
)
def test_safe_result_external_id_is_printable_and_bounded(
    value: object,
    expected: str,
) -> None:
    assert safe_publication_external_id_for_error(value) == expected


def test_normal_unicode_publication_text_remains_supported() -> None:
    normalized = normalize_publication_candidate(
        candidate(
            source_external_id="تقرير-2026-001",
            title="تنبيه أمني للمنطقة",
            summary="ملخص آمن لمعلومات الأمن السيبراني.",
            payload={"source_id": "تقرير-2026-001", "category": "أمن سيبراني"},
        )
    )

    assert normalized.source_external_id == "تقرير-2026-001"
    assert normalized.canonical_title == "تنبيه أمني للمنطقة"
    assert normalized.summary == "ملخص آمن لمعلومات الأمن السيبراني."
    assert normalized.raw_payload["category"] == "أمن سيبراني"
    assert len(normalized.normalized_title_hash) == 64
    assert len(normalized.content_hash) == 64


def test_raw_url_length_is_checked_before_query_stripping() -> None:
    prefix = "https://cert.europa.eu/"
    accepted_url = prefix + ("a" * (MAX_PUBLICATION_URL_LENGTH - len(prefix)))
    oversized_url = accepted_url + "x"
    tracking_heavy_url = (
        "https://cert.europa.eu/publications/x?utm_source="
        + ("x" * MAX_PUBLICATION_URL_LENGTH)
    )

    assert canonicalize_publication_url(RSS_SOURCE_SLUG, accepted_url) == accepted_url
    for url in (oversized_url, tracking_heavy_url):
        with pytest.raises(PublicationCandidateError) as exc_info:
            canonicalize_publication_url(RSS_SOURCE_SLUG, url)
        assert url not in str(exc_info.value)


def test_safe_payload_is_defensively_snapshotted() -> None:
    categories = ["Advisory"]
    payload = {"source_id": "CERT-EU-SA2026-001", "categories": categories}
    record = candidate(payload=payload)
    payload["source_id"] = "changed"
    categories.append("Changed")

    normalized = normalize_publication_candidate(record)

    assert normalized.raw_payload == {
        "categories": ["Advisory"],
        "source_id": "CERT-EU-SA2026-001",
    }


def test_safe_payload_limits_and_sensitive_keys_are_enforced() -> None:
    with pytest.raises(PublicationCandidateError):
        candidate(payload={f"k{i}": "value" for i in range(MAX_SAFE_PAYLOAD_KEYS + 1)})
    with pytest.raises(PublicationCandidateError):
        candidate(payload={"categories": ["x"] * (MAX_SAFE_PAYLOAD_SEQUENCE_ITEMS + 1)})
    with pytest.raises(PublicationCandidateError):
        candidate(payload={"summary": "x" * (MAX_SAFE_PAYLOAD_BYTES + 1)})
    with pytest.raises(PublicationCandidateError) as exc_info:
        candidate(payload={"Access_Token": "super-secret-value"})
    assert "super-secret-value" not in str(exc_info.value)
    with pytest.raises(PublicationCandidateError):
        candidate(payload={"score": float("nan")})


@pytest.mark.parametrize(
    ("payload", "rejected_key", "rejected_value"),
    [
        ({"unsafe\x00key": "ordinary-value"}, "unsafe\x00key", "ordinary-value"),
        ({"category": "unsafe\x00value"}, "category", "unsafe\x00value"),
        ({"categories": ["safe", "unsafe\x00member"]}, "categories", "unsafe\x00member"),
        ({"category": "unsafe\ud800value"}, "category", "unsafe\ud800value"),
    ],
)
def test_database_unsafe_payload_text_fails_without_disclosure(
    payload: dict[str, object],
    rejected_key: str,
    rejected_value: str,
) -> None:
    with pytest.raises(PublicationCandidateError) as exc_info:
        candidate(payload=payload)

    message = str(exc_info.value)
    assert rejected_key not in message
    assert rejected_value not in message
    assert "Unicode" not in message


@pytest.mark.parametrize(
    "key",
    [
        "sig",
        "CLIENT-SECRET",
        "auth.token",
        "ID_TOKEN",
        "session-token",
        "sas.token",
        "bearer_token",
        "X-API-KEY",
        "\uff38\uff3f\uff21\uff30\uff29\uff3f\uff2b\uff25\uff39",
        "secret.key",
        "token",
        "API_TOKEN",
        "api.token.value",
        "OAuth_Token",
        "oauth2-token",
        "jwt",
        "JWT_TOKEN",
        "PRIVATE-KEY",
        "access.key",
        "SECRET_ACCESS_KEY",
        "AWSAccessKeyId",
        "aws_access_key_id",
        "google-access-id",
        "x-amz-credential",
        "x-amz-security-token",
        "x-goog-credential",
        "x-goog-security-token",
    ],
)
def test_sensitive_payload_aliases_are_rejected_without_disclosure(key: str) -> None:
    with pytest.raises(PublicationCandidateError) as exc_info:
        candidate(payload={key: "credential-value"})

    message = str(exc_info.value)
    assert key not in message
    assert "credential-value" not in message


def test_similar_noncredential_payload_keys_remain_allowed() -> None:
    normalized = normalize_publication_candidate(
        candidate(
            payload={
                "signal": "high",
                "tokenization": "enabled",
                "signature_version": "4",
                "private_key_algorithm": "RSA",
                "client_id": "public-id",
                "client_identifier": "public",
                "accessibility": "enabled",
            }
        )
    )

    assert normalized.raw_payload == {
        "accessibility": "enabled",
        "client_id": "public-id",
        "client_identifier": "public",
        "private_key_algorithm": "RSA",
        "signal": "high",
        "signature_version": "4",
        "tokenization": "enabled",
    }


def test_normal_cert_eu_safe_payload_succeeds() -> None:
    normalized = normalize_publication_candidate(
        candidate(
            payload={
                "source_id": "CERT-EU-SA2026-001",
                "categories": ["Advisory"],
                "published_utc": "2026-07-08T08:30:00+00:00",
            }
        )
    )

    assert normalized.raw_payload["categories"] == ["Advisory"]


def test_pipeline_persists_new_publication_with_safe_article_fields() -> None:
    session = FakeSession()

    result = PublicationPipeline(session).persist(
        candidate(), observed_at=OBSERVED_AT
    )  # type: ignore[arg-type]

    assert result.outcome == "created"
    assert len(session.sources) == 1
    assert len(session.items) == 1
    assert len(session.source_records) == 1
    assert len(session.identifiers) == 2
    source = session.sources[0]
    item = session.items[0]
    source_record = session.source_records[0]
    assert source.slug == RSS_SOURCE_SLUG
    assert item.item_type == "security_advisory"
    assert item.canonical_title == "CERT-EU Security Advisory"
    assert item.summary == "Safe advisory summary."
    assert item.data_confidence == Decimal("0.900")
    assert item.status == "active"
    assert source_record.raw_payload == {"source_id": "CERT-EU-SA2026-001"}
    assert {
        (identifier.namespace, identifier.source_id, identifier.is_primary)
        for identifier in session.identifiers
    } == {
        (ARTICLE_URL_IDENTIFIER_NAMESPACE, None, False),
        (ARTICLE_TITLE_IDENTIFIER_NAMESPACE, None, False),
    }
    assert session.commits == 0
    assert session.rollbacks == 0


def test_pipeline_process_candidates_counts_created_and_unchanged_results() -> None:
    session = FakeSession()

    batch = PublicationPipeline(session).process_candidates(
        [candidate(), candidate()],
        observed_at=OBSERVED_AT,
    )

    assert batch.total == 2
    assert batch.created == 1
    assert batch.unchanged == 1
    assert batch.updated == 0
    assert batch.skipped == 0
    assert batch.failed == 0
    assert batch.total == (
        batch.created
        + batch.updated
        + batch.unchanged
        + batch.skipped
        + batch.failed
    )
    assert len(session.items) == 1
    assert session.commits == 0
    assert session.rollbacks == 0


def test_database_exceptions_are_sanitized_and_not_committed() -> None:
    session = FakeSession(fail_flush=True)

    with pytest.raises(PublicationPersistenceError) as exc_info:
        PublicationPipeline(session).persist(
            candidate(), observed_at=OBSERVED_AT
        )  # type: ignore[arg-type]

    assert "private" not in str(exc_info.value)
    assert session.commits == 0
    assert session.rollbacks == 0


def test_pipeline_makes_no_network_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network must not be used")

    monkeypatch.setattr(socket, "create_connection", fail_network)

    result = PublicationPipeline(FakeSession()).persist(
        candidate(),
        observed_at=OBSERVED_AT,
    )

    assert result.outcome == "created"


def test_rss_adapter_uses_publication_pipeline_without_changing_hashes() -> None:
    body = b"""<rss><channel><item>
<guid>CERT-EU-SA2026-001</guid>
<title>CERT-EU Security Advisory</title>
<link>https://cert.europa.eu/publications/security-advisories/2026-001?b=2&utm_source=x&a=1#g</link>
<description>Safe advisory summary.</description>
<pubDate>Wed, 08 Jul 2026 08:30:00 GMT</pubDate>
</item></channel></rss>"""
    rss_record = normalize_rss_feed(body)[0]
    normalized = normalize_publication_candidate(
        candidate(
            source_external_id=rss_record.source_external_id,
            title=rss_record.canonical_title,
            url=rss_record.canonical_url,
            summary=rss_record.summary,
            published_at=rss_record.source_published_at,
            payload=rss_record.raw_payload,
        )
    )

    session = FakeSession()
    result = RssIngestionService(session).persist(  # type: ignore[arg-type]
        rss_record,
        observed_at=OBSERVED_AT,
    )

    assert normalized.content_hash == rss_record.content_hash
    assert normalized.canonical_url_hash == rss_record.canonical_url_hash
    assert normalized.normalized_title_hash == rss_record.normalized_title_hash
    assert result.outcome == "created"
    assert session.source_records[0].content_hash == rss_record.content_hash
    assert session.items[0].item_type == "security_advisory"
