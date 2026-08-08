from __future__ import annotations

from decimal import Decimal

import pytest

from app.processing.uae_relevance_classifier import (
    UAE_CLASSIFICATION_SOURCE_SLUGS,
    UAE_RELEVANCE_CONFIDENCE_BY_RULE,
    UaeClassificationInput,
    classify_uae_relevance,
    confidence_for_rule,
    normalize_text,
)


def classify(title: str | None = None, summary: str | None = None, **kwargs):
    return classify_uae_relevance(
        UaeClassificationInput(title=title, summary=summary, **kwargs)
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ""),
        ("", ""),
        ("  Dubai\t\tAdvisory\nUpdate  ", "dubai advisory update"),
        ("ＵＡＥ security", "uae security"),
        ("Ras al-Khaimah", "ras al khaimah"),
        ("United_Arab_Emirates", "united arab emirates"),
    ],
)
def test_text_normalization_is_unicode_safe_and_stable(value, expected) -> None:
    first = normalize_text(value)

    assert first == expected
    assert normalize_text(value) == first


def test_bounded_oversized_input_is_deterministic() -> None:
    text = "A" * 9000 + " Dubai"

    assert normalize_text(text) == "a" * 8000
    assert classify(text).matched_rule_id == "no_direct_uae_evidence"


@pytest.mark.parametrize(
    "text",
    [
        "United Arab Emirates",
        "UNITED   ARAB   EMIRATES advisory",
        "Patch notice for the United-Arab-Emirates public sector",
    ],
)
def test_country_phrase_matches(text: str) -> None:
    result = classify(text)

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "possible"
    assert result.matched_rule_id == "text_country_mention"
    assert result.uae_relevance_confidence == Decimal("0.650")
    assert "no attribution asserted" in result.uae_relevance_reason


@pytest.mark.parametrize(
    "text",
    ["UAE alert", "U.A.E. alert", "u.a.e advisory", "UAE_alert"],
)
def test_standalone_uae_acronym_matches(text: str) -> None:
    result = classify(text)

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "possible"
    assert result.matched_rule_id == "text_uae_acronym_mention"
    assert result.uae_relevance_confidence == Decimal("0.600")


@pytest.mark.parametrize(
    "text",
    [
        "Abu Dhabi",
        "Dubai",
        "Sharjah",
        "Ajman",
        "Fujairah",
        "Ras Al Khaimah",
        "Ras al-Khaimah",
        "Ras_Al_Khaimah",
        "Umm Al Quwain",
        "Umm al-Quwain",
        "Abu_Dhabi",
        "incident affecting DUBAI.",
    ],
)
def test_emirate_names_match(text: str) -> None:
    result = classify(text)

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "possible"
    assert result.matched_rule_id == "text_emirate_mention"
    assert result.uae_relevance_confidence == Decimal("0.550")
    assert "no attribution asserted" in result.uae_relevance_reason


@pytest.mark.parametrize(
    "text",
    [
        "blueuaevalue",
        "blue_uaevalue",
        "Middle East advisory",
        "GCC cyber update",
        "MENA threat report",
        "Arabian Gulf sector alert",
        "Gulf banking alert",
        "banking finance oil gas energy aviation telecommunications government critical infrastructure",
    ],
)
def test_global_content_without_direct_evidence_is_not_relevant(text: str) -> None:
    result = classify(text, geographic_scope="global")

    assert result.geographic_scope == "global"
    assert result.uae_relevance_status == "not_relevant"
    assert result.matched_rule_id == "explicit_global_scope"
    assert result.uae_relevance_confidence == Decimal("0.800")
    assert result.uae_relevance_reason == "Global relevance with no demonstrated UAE-specific evidence."


def test_approved_canonical_source_slug_matches_without_url_or_display_trust() -> None:
    result = classify(
        "Generic cyber advisory",
        source_slugs=("uae-cyber-security-council",),
    )

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == "approved_uae_source"
    assert result.uae_relevance_confidence == Decimal("0.950")


def test_classification_source_boundary_is_not_network_approval_or_registry_sync() -> None:
    assert UAE_CLASSIFICATION_SOURCE_SLUGS == {
        "ae-cert",
        "desc-news",
        "desc-published-research",
        "uae-cert",
        "uae-cyber-security-council",
        "uae-cyber-security-council-nibras",
    }
    assert "uae-cert" in UAE_CLASSIFICATION_SOURCE_SLUGS
    assert "uae-cyber-security-council-nibras" in UAE_CLASSIFICATION_SOURCE_SLUGS


@pytest.mark.parametrize(
    "slug",
    ["uae-cyber-security-council-news", "fake-uae-cert", "https://example.com/uae-cert"],
)
def test_unapproved_source_slug_does_not_create_trust(slug: str) -> None:
    result = classify("Generic advisory", source_slugs=(slug,))

    assert result.uae_relevance_status == "unknown"
    assert result.matched_rule_id == "no_direct_uae_evidence"


def test_strongest_rule_wins_and_output_is_stable() -> None:
    first = classify(
        "Dubai advisory for United Arab Emirates organizations",
        source_slugs=("uae-cert",),
    )
    second = classify(
        summary="Dubai advisory for United Arab Emirates organizations",
        source_slugs=("uae-cert",),
    )

    assert first == second
    assert first.matched_rule_id == "approved_uae_source"
    assert first.uae_relevance_confidence == Decimal("0.950")
    assert first.uae_relevance_reason == "Direct UAE authority-source evidence."


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("approved_uae_source", Decimal("0.950")),
        ("text_country_mention", Decimal("0.650")),
        ("text_uae_acronym_mention", Decimal("0.600")),
        ("text_emirate_mention", Decimal("0.550")),
        ("explicit_global_scope", Decimal("0.800")),
        ("no_direct_uae_evidence", None),
    ],
)
def test_confidence_mapping_values_are_decimal_and_bounded(
    rule_id: str,
    expected: Decimal | None,
) -> None:
    value = confidence_for_rule(rule_id)

    assert value == expected
    if value is not None:
        assert isinstance(value, Decimal)
        assert Decimal("0") <= value <= Decimal("1")
        assert value.as_tuple().exponent == -3


def test_unknown_confidence_rule_fails_safely() -> None:
    with pytest.raises(ValueError, match="Unknown UAE relevance confidence rule"):
        confidence_for_rule("not_a_rule")


def test_invalid_internal_confidence_mapping_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_mapping = dict(UAE_RELEVANCE_CONFIDENCE_BY_RULE)
    invalid_mapping["direct_country_name"] = Decimal("1.001")
    monkeypatch.setattr(
        "app.processing.uae_relevance_classifier.UAE_RELEVANCE_CONFIDENCE_BY_RULE",
        invalid_mapping,
    )

    with pytest.raises(ValueError, match="outside 0..1"):
        confidence_for_rule("direct_country_name")


def test_non_decimal_internal_confidence_mapping_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_mapping = dict(UAE_RELEVANCE_CONFIDENCE_BY_RULE)
    invalid_mapping["direct_country_name"] = 0.95
    monkeypatch.setattr(
        "app.processing.uae_relevance_classifier.UAE_RELEVANCE_CONFIDENCE_BY_RULE",
        invalid_mapping,
    )

    with pytest.raises(ValueError, match="Decimal or None"):
        confidence_for_rule("direct_country_name")


def test_non_finite_internal_confidence_mapping_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_mapping = dict(UAE_RELEVANCE_CONFIDENCE_BY_RULE)
    invalid_mapping["direct_country_name"] = Decimal("NaN")
    monkeypatch.setattr(
        "app.processing.uae_relevance_classifier.UAE_RELEVANCE_CONFIDENCE_BY_RULE",
        invalid_mapping,
    )

    with pytest.raises(ValueError, match="must be finite"):
        confidence_for_rule("direct_country_name")


def test_over_precise_internal_confidence_mapping_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_mapping = dict(UAE_RELEVANCE_CONFIDENCE_BY_RULE)
    invalid_mapping["direct_country_name"] = Decimal("0.9501")
    monkeypatch.setattr(
        "app.processing.uae_relevance_classifier.UAE_RELEVANCE_CONFIDENCE_BY_RULE",
        invalid_mapping,
    )

    with pytest.raises(ValueError, match="Numeric\\(4,3\\)"):
        confidence_for_rule("direct_country_name")


def test_repeated_mentions_do_not_inflate_confidence() -> None:
    once = classify("Dubai advisory")
    repeated = classify("Dubai Dubai Dubai advisory")

    assert once.matched_rule_id == repeated.matched_rule_id == "text_emirate_mention"
    assert once.uae_relevance_confidence == repeated.uae_relevance_confidence


def test_title_and_summary_order_does_not_change_confidence() -> None:
    title_match = classify(title="UAE advisory", summary="General summary")
    summary_match = classify(title="General title", summary="UAE advisory")

    assert title_match.matched_rule_id == summary_match.matched_rule_id
    assert title_match.uae_relevance_confidence == Decimal("0.600")
    assert summary_match.uae_relevance_confidence == Decimal("0.600")


@pytest.mark.parametrize(
    ("title", "summary"),
    [
        ("United Arab", "Emirates advisory"),
        ("U", "A E advisory"),
        ("Abu", "Dhabi advisory"),
        ("Ras Al", "Khaimah advisory"),
    ],
)
def test_direct_text_rules_do_not_match_across_field_boundaries(
    title: str,
    summary: str,
) -> None:
    result = classify(title=title, summary=summary)

    assert result.uae_relevance_status == "unknown"
    assert result.matched_rule_id == "no_direct_uae_evidence"
    assert result.uae_relevance_confidence is None


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [
        ("United_Arab_Emirates advisory", "text_country_mention"),
        ("UAE_alert", "text_uae_acronym_mention"),
        ("Abu_Dhabi advisory", "text_emirate_mention"),
        ("Ras_Al_Khaimah advisory", "text_emirate_mention"),
    ],
)
def test_underscores_are_safe_classification_separators(
    text: str,
    rule_id: str,
) -> None:
    result = classify(text)

    assert result.uae_relevance_status == "possible"
    assert result.matched_rule_id == rule_id
    assert result.uae_relevance_confidence == confidence_for_rule(rule_id)


def test_underscore_normalization_still_rejects_acronym_substrings() -> None:
    result = classify("blue_uaevalue advisory")

    assert result.uae_relevance_status == "unknown"
    assert result.matched_rule_id == "no_direct_uae_evidence"
    assert result.uae_relevance_confidence is None
