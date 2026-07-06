from datetime import datetime
from decimal import Decimal
from urllib.parse import urlparse

from app.dev_data.dataset import (
    SAFE_DOMAIN_SUFFIXES,
    SEED_DATASET,
    SEED_IDENTIFIER_NAMESPACE,
    validate_seed_dataset,
)
from app.models.intelligence_item import (
    GEOGRAPHIC_SCOPE_VALUES,
    ITEM_TYPE_VALUES,
    STATUS_VALUES,
    UAE_RELEVANCE_METHOD_VALUES,
    UAE_RELEVANCE_STATUS_VALUES,
)
from app.models.intelligence_item_tag import ASSIGNED_BY_VALUES
from app.models.intelligence_source import SOURCE_TYPE_VALUES
from app.models.tag import TAG_TYPE_VALUES
from app.models.vulnerability import KEV_STATUS_VALUES, SEVERITY_VALUES


def test_seed_dataset_has_expected_record_counts():
    assert len(SEED_DATASET.sources) == 4
    assert len(SEED_DATASET.tags) == 12
    assert len(SEED_DATASET.items) == 10
    assert SEED_DATASET.identifier_count == 14
    assert SEED_DATASET.vulnerability_count == 4
    assert SEED_DATASET.source_record_count == 10
    assert SEED_DATASET.item_tag_association_count == 36


def test_seed_dataset_validation_passes():
    result = validate_seed_dataset(SEED_DATASET)

    assert result.errors == ()


def test_seed_dataset_uses_safe_example_domains_only():
    urls = [source.base_url for source in SEED_DATASET.sources]
    urls.extend(item.canonical_url for item in SEED_DATASET.items)
    urls.extend(item.source_record.source_url for item in SEED_DATASET.items)

    for url in urls:
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.hostname in SAFE_DOMAIN_SUFFIXES


def test_seed_dataset_timestamps_are_timezone_aware():
    timestamps: list[datetime] = []
    for item in SEED_DATASET.items:
        timestamps.extend(
            [
                item.source_published_at,
                item.collected_at,
                item.last_seen_at,
                item.source_record.source_published_at,
            ]
        )
        if item.source_modified_at is not None:
            timestamps.append(item.source_modified_at)
        if item.source_record.source_modified_at is not None:
            timestamps.append(item.source_record.source_modified_at)
        if item.vulnerability and item.vulnerability.kev_last_checked_at is not None:
            timestamps.append(item.vulnerability.kev_last_checked_at)

    for timestamp in timestamps:
        assert timestamp.tzinfo is not None
        assert timestamp.utcoffset() is not None


def test_seed_dataset_values_match_model_controlled_values():
    for source in SEED_DATASET.sources:
        assert source.source_type in SOURCE_TYPE_VALUES

    for tag in SEED_DATASET.tags:
        assert tag.tag_type in TAG_TYPE_VALUES

    for item in SEED_DATASET.items:
        assert item.item_type in ITEM_TYPE_VALUES
        assert item.status in STATUS_VALUES
        assert item.geographic_scope in GEOGRAPHIC_SCOPE_VALUES
        assert item.uae_relevance_status in UAE_RELEVANCE_STATUS_VALUES
        assert item.uae_relevance_method in UAE_RELEVANCE_METHOD_VALUES
        assert item.tag_assignment_source in ASSIGNED_BY_VALUES
        if item.vulnerability is not None:
            assert item.vulnerability.severity in SEVERITY_VALUES
            assert item.vulnerability.kev_status in KEV_STATUS_VALUES


def test_seed_dataset_numeric_values_are_in_allowed_ranges():
    for item in SEED_DATASET.items:
        assert Decimal("0") <= item.data_confidence <= Decimal("1")
        assert Decimal("0") <= item.tag_confidence <= Decimal("1")
        if item.uae_relevance_confidence is not None:
            assert Decimal("0") <= item.uae_relevance_confidence <= Decimal("1")
        if item.vulnerability is not None:
            vulnerability = item.vulnerability
            assert vulnerability.cvss_score is not None
            assert Decimal("0") <= vulnerability.cvss_score <= Decimal("10")
            assert vulnerability.epss_score is not None
            assert Decimal("0") <= vulnerability.epss_score <= Decimal("1")
            assert vulnerability.epss_percentile is not None
            assert Decimal("0") <= vulnerability.epss_percentile <= Decimal("1")


def test_seed_dataset_references_are_defined_and_identifiers_are_unique():
    source_slugs = {source.slug for source in SEED_DATASET.sources}
    tag_slugs = {tag.slug for tag in SEED_DATASET.tags}
    source_public_ids = {source.public_id for source in SEED_DATASET.sources}
    item_public_ids = {item.public_id for item in SEED_DATASET.items}
    non_seed_identifiers = set()

    assert len(source_public_ids) == len(SEED_DATASET.sources)
    assert len(item_public_ids) == len(SEED_DATASET.items)

    for item in SEED_DATASET.items:
        assert item.source_record.source_slug in source_slugs
        assert set(item.tag_slugs) <= tag_slugs
        assert any(
            identifier.namespace == SEED_IDENTIFIER_NAMESPACE
            and identifier.normalized_value == item.seed_key
            for identifier in item.identifiers
        )
        for identifier in item.identifiers:
            if identifier.namespace != SEED_IDENTIFIER_NAMESPACE:
                key = (identifier.namespace, identifier.normalized_value)
                assert key not in non_seed_identifiers
                non_seed_identifiers.add(key)


def test_seed_dataset_text_respects_database_limits_and_safety_boundaries():
    forbidden = (
        "api_key",
        "authorization:",
        "bearer ",
        "cookie:",
        "password=",
        "postgresql://",
        "postgresql+psycopg://",
        "secret",
        "token=",
        "curl ",
        "meterpreter",
        "msfconsole",
        "powershell -enc",
        "reverse shell",
        "rm -rf",
        "<script",
    )

    for source in SEED_DATASET.sources:
        assert len(source.slug) <= 80
        assert len(source.name) <= 160
        assert len(source.rate_limit_notes) <= 500

    for tag in SEED_DATASET.tags:
        assert len(tag.slug) <= 100
        assert len(tag.display_name) <= 120

    for item in SEED_DATASET.items:
        text_values = [
            item.seed_key,
            item.canonical_title,
            item.summary,
            item.uae_relevance_reason or "",
        ]
        assert len(item.canonical_title) <= 500
        assert len(item.canonical_url) <= 2048
        assert item.source_record.source_external_id == item.seed_key
        assert len(item.source_record.source_url) <= 2048
        for identifier in item.identifiers:
            assert len(identifier.namespace) <= 40
            assert len(identifier.value) <= 300
            assert len(identifier.normalized_value) <= 300
            text_values.extend(
                [identifier.namespace, identifier.value, identifier.normalized_value]
            )
        if item.vulnerability is not None:
            vulnerability = item.vulnerability
            text_values.extend(
                [
                    vulnerability.cvss_vector or "",
                    vulnerability.cvss_version or "",
                    vulnerability.kev_required_action or "",
                    vulnerability.affected_summary,
                ]
            )

        lowered = "\n".join(text_values).lower()
        assert all(fragment not in lowered for fragment in forbidden)
