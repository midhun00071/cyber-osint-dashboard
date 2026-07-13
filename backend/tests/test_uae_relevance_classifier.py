from __future__ import annotations

import pytest

from app.processing.uae_relevance_classifier import (
    UaeClassificationInput,
    classify_uae_relevance,
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
    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == "direct_country_name"
    assert result.uae_relevance_reason == "Matched direct UAE country phrase."


@pytest.mark.parametrize(
    "text",
    ["UAE alert", "U.A.E. alert", "u.a.e advisory", "UAE_alert"],
)
def test_standalone_uae_acronym_matches(text: str) -> None:
    result = classify(text)

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == "direct_uae_acronym"


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
    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == "direct_emirate_name"
    assert result.uae_relevance_reason.startswith("Matched emirate name:")


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
def test_regional_and_sector_terms_alone_remain_unknown(text: str) -> None:
    result = classify(text, geographic_scope="global")

    assert result.geographic_scope == "global"
    assert result.uae_relevance_status == "unknown"
    assert result.matched_rule_id == "no_direct_uae_evidence"
    assert result.uae_relevance_reason == "No direct UAE evidence found."


def test_approved_canonical_source_slug_matches_without_url_or_display_trust() -> None:
    result = classify(
        "Generic cyber advisory",
        source_slugs=("uae-cyber-security-council",),
    )

    assert result.geographic_scope == "uae"
    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == "approved_uae_source"


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
    assert first.uae_relevance_reason == "Matched approved UAE source."


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


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [
        ("United_Arab_Emirates advisory", "direct_country_name"),
        ("UAE_alert", "direct_uae_acronym"),
        ("Abu_Dhabi advisory", "direct_emirate_name"),
        ("Ras_Al_Khaimah advisory", "direct_emirate_name"),
    ],
)
def test_underscores_are_safe_classification_separators(
    text: str,
    rule_id: str,
) -> None:
    result = classify(text)

    assert result.uae_relevance_status == "confirmed"
    assert result.matched_rule_id == rule_id


def test_underscore_normalization_still_rejects_acronym_substrings() -> None:
    result = classify("blue_uaevalue advisory")

    assert result.uae_relevance_status == "unknown"
    assert result.matched_rule_id == "no_direct_uae_evidence"
