from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import httpx
import pytest

from app.ingestion.collectors import desc_publications_client as module
from app.ingestion.collectors.desc_publications_client import (
    ACCEPT_HEADER,
    MAX_DOM_NODES,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    DescApprovalPendingError,
    DescCollectionResult,
    DescContentTypeError,
    DescHttpError,
    DescMetadataError,
    DescPublicationSource,
    DescPublicationsClient,
    DescRateLimitError,
    DescRedirectError,
    DescRejectionCategory,
    DescResponseTooLargeError,
    parse_desc_publications,
)


def news_article(slug: str = "safe-news", *, title: str = "Safe DESC News", date: str = "2026-08-01T10:00:00+04:00", href: str | None = None) -> str:
    url = href or f"https://www.desc.gov.ae/{slug}/"
    return f"""
    <article class="post type-post category-news">
      <a class="post-thumbnail" href="{url}"><img src="ignored.jpg"></a>
      <h2 class="entry-title"><a href="{url}">{title}</a></h2>
      <a href="{url}"><time class="entry-date published" datetime="{date}">display</time></a>
      <div class="entry-summary">Bounded listing summary. <a class="read-more" href="{url}">Read More</a></div>
    </article>"""


def research_card(*, title: str = "Secure Systems Study", url: str = "https://ieeexplore.ieee.org/document/12345", statement: str = "Published in Example Journal, July 2026", publishers: str = "DESC and University") -> str:
    return f"""
    <section class="elementor-section elementor-inner-section">
      <h4 class="elementor-heading-title">{title}</h4>
      <h6 class="elementor-heading-title">{statement}</h6>
      <p><strong>Publishers:</strong> {publishers}</p>
      <a href="https://www.desc.gov.ae/wp-content/uploads/paper.pdf">Download Research Paper</a>
      <a href="{url}">Visit Publication</a>
    </section>"""


def test_news_parser_accepts_multiple_records_and_ignores_untrusted_links() -> None:
    html = ("<nav><h2><a href='https://evil.example/x'>Ignore</a></h2></nav>" + news_article("first-news") + news_article("second-news", title="Second News")).encode()
    result = parse_desc_publications(DescPublicationSource.NEWS, html)

    assert [item.source_external_id for item in result.candidates] == ["desc-news:first-news", "desc-news:second-news"]
    assert result.candidates[0].summary == "Bounded listing summary."
    assert result.candidates[0].source_published_at.utcoffset() is not None
    assert result.rejected_record_count == 0
    assert "<article" not in repr(result)


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://www.desc.gov.ae/bad/", "https://www.desc.gov.ae:443/bad/",
        "https://user@www.desc.gov.ae/bad/", "https://www.desc.gov.ae.evil.test/bad/",
        "https://sub.www.desc.gov.ae/bad/", "https://www.desc.gov.ae./bad/",
        "https://127.0.0.1/bad/", "https://[::1]/bad/", "https://www.desc.gov.ae/bad/?x=1",
        "https://www.desc.gov.ae/bad/#x", "https://www.desc.gov.ae/%62ad/",
        "https://www.desc.gov.ae/%2e%2e/", "https://www.desc.gov.ae/bad\\x/",
        "https://www.desc.gov.ae/bad;x/", "https://www.desc.gov.ae/nested/bad/",
        "https://www.desc.gov.ae/page/2/", "https://www.desc.gov.ae/wp-json/",
        " https://www.desc.gov.ae/bad/", "https://www.desc.gov.ae/bad/\n",
    ],
)
def test_news_url_boundary_rejections_are_counted(bad_url: str) -> None:
    html = (news_article("good") + news_article("bad", href=bad_url)).encode()
    result = parse_desc_publications(DescPublicationSource.NEWS, html)
    assert len(result.candidates) == 1
    assert result.rejected_record_count == 1
    assert {item.value for item in result.rejection_categories} == {"unsafe_url"}


def test_news_ambiguous_links_and_bad_dates_are_rejected() -> None:
    ambiguous = news_article("one").replace(
        '<a class="read-more" href="https://www.desc.gov.ae/one/">',
        '<a class="read-more" href="https://www.desc.gov.ae/other/">',
    )
    result = parse_desc_publications(
        DescPublicationSource.NEWS,
        (news_article("good") + ambiguous + news_article("naive", date="2026-08-01T10:00:00")).encode(),
    )
    assert len(result.candidates) == 1
    assert result.rejected_record_count == 2
    assert {item.value for item in result.rejection_categories} == {"ambiguous", "invalid_date"}


def test_news_duplicate_collapse_conflict_and_record_cap() -> None:
    exact = parse_desc_publications(DescPublicationSource.NEWS, (news_article("same") * 2).encode())
    assert len(exact.candidates) == 1
    capped = parse_desc_publications(DescPublicationSource.NEWS, (news_article("one") + news_article("two")).encode(), max_records=1)
    assert capped.record_limit_exceeded is True
    assert capped.rejected_record_count == 1
    conflict_html = news_article("same") + news_article("same", title="Conflicting") + news_article("good")
    conflict = parse_desc_publications(DescPublicationSource.NEWS, conflict_html.encode())
    assert [item.source_external_id for item in conflict.candidates] == ["desc-news:good"]
    assert conflict.rejected_record_count == 2


def test_record_cap_counts_trusted_news_containers_before_deduplication() -> None:
    distinct = "".join(news_article(f"news-{index}") for index in range(51))
    distinct_result = parse_desc_publications(DescPublicationSource.NEWS, distinct.encode())
    assert len(distinct_result.candidates) == 50
    assert distinct_result.rejected_record_count == 1
    assert distinct_result.record_limit_exceeded is True
    assert DescRejectionCategory.RECORD_LIMIT in distinct_result.rejection_categories

    identical_result = parse_desc_publications(
        DescPublicationSource.NEWS,
        (news_article("same") * 51).encode(),
    )
    assert len(identical_result.candidates) == 1
    assert identical_result.rejected_record_count == 1
    assert identical_result.record_limit_exceeded is True
    assert identical_result.rejection_categories == (
        DescRejectionCategory.RECORD_LIMIT,
    )


def test_record_cap_counts_research_duplicates_and_malformed_selected_records() -> None:
    identical = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (research_card() * 51).encode(),
    )
    assert len(identical.candidates) == 1
    assert identical.rejected_record_count == 1
    assert identical.record_limit_exceeded is True

    selected = "".join(news_article(f"good-{index}") for index in range(49))
    malformed = news_article("malformed").replace("entry-title", "not-a-title")
    overflow = news_article("overflow-one") + news_article("overflow-two")
    mixed = parse_desc_publications(
        DescPublicationSource.NEWS,
        (selected + malformed + overflow).encode(),
    )
    assert len(mixed.candidates) == 49
    assert mixed.rejected_record_count == 3
    assert mixed.rejection_categories == (
        DescRejectionCategory.RECORD_LIMIT,
        DescRejectionCategory.STRUCTURE,
    )
    assert all(candidate.canonical_title != "Safe DESC News" or "overflow" not in candidate.canonical_url for candidate in mixed.candidates)


def _valid_result_kwargs() -> dict[str, object]:
    candidate = parse_desc_publications(
        DescPublicationSource.NEWS,
        news_article().encode(),
    ).candidates[0]
    return {
        "source": DescPublicationSource.NEWS,
        "source_slug": "desc-news",
        "candidates": (candidate,),
        "rejected_record_count": 0,
        "rejection_categories": (),
        "fetched_listing_page_count": 1,
        "record_limit_exceeded": False,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"rejected_record_count": -1},
        {"rejected_record_count": True},
        {"rejected_record_count": "1"},
        {"rejected_record_count": 1, "record_limit_exceeded": True, "rejection_categories": ()},
        {"rejected_record_count": 1, "record_limit_exceeded": False, "rejection_categories": (DescRejectionCategory.RECORD_LIMIT,)},
        {"rejected_record_count": 0, "record_limit_exceeded": True, "rejection_categories": (DescRejectionCategory.RECORD_LIMIT,)},
        {"rejected_record_count": 1, "rejection_categories": ()},
        {"rejected_record_count": 0, "rejection_categories": (DescRejectionCategory.STRUCTURE,)},
        {"source_slug": "desc-published-research"},
        {"candidates": []},
        {"rejection_categories": [DescRejectionCategory.STRUCTURE]},
        {"rejected_record_count": 2, "rejection_categories": (DescRejectionCategory.STRUCTURE, DescRejectionCategory.STRUCTURE)},
        {"fetched_listing_page_count": 2},
        {"fetched_listing_page_count": True},
        {"record_limit_exceeded": 1},
    ],
)
def test_collection_result_invariants_reject_malformed_values(
    overrides: dict[str, object],
) -> None:
    values = _valid_result_kwargs()
    values.update(overrides)
    with pytest.raises(ValueError, match="DESC collection"):
        DescCollectionResult(**values)  # type: ignore[arg-type]


def test_collection_result_rejects_too_many_duplicate_and_wrong_source_candidates() -> None:
    values = _valid_result_kwargs()
    candidate = values["candidates"][0]  # type: ignore[index]
    too_many = tuple(
        replace(candidate, source_external_id=f"desc-news:item-{index}")
        for index in range(51)
    )
    for candidates in (
        too_many,
        (candidate, candidate),
        (replace(candidate, source_slug="desc-published-research"),),
    ):
        with pytest.raises(ValueError, match="DESC collection"):
            DescCollectionResult(**{**values, "candidates": candidates})  # type: ignore[arg-type]


def test_deeply_nested_dom_uses_bounded_iterative_traversal() -> None:
    depth = 4_000
    nested_title = "<span>" * depth + "Deep Safe News" + "</span>" * depth
    news = news_article("deep-news", title=nested_title)
    first = parse_desc_publications(DescPublicationSource.NEWS, news.encode())
    second = parse_desc_publications(DescPublicationSource.NEWS, news.encode())
    assert first.candidates == second.candidates
    assert first.candidates[0].canonical_title == "Deep Safe News"

    nested_summary = "<span>" * depth + "Deep Safe Summary" + "</span>" * depth
    summary_news = news_article("deep-summary").replace(
        "Bounded listing summary.", nested_summary
    )
    summary_result = parse_desc_publications(
        DescPublicationSource.NEWS,
        summary_news.encode(),
    )
    assert summary_result.candidates[0].summary == "Deep Safe Summary"

    nested_research_title = "<span>" * depth + "Deep Research" + "</span>" * depth
    research = research_card(title=nested_research_title)
    research_result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        research.encode(),
    )
    assert research_result.candidates[0].canonical_title == "Deep Research"


def test_dom_node_limit_failure_is_sanitized_without_recursion_error() -> None:
    marker = "provider-controlled-marker"
    html = ("<div>" * (MAX_DOM_NODES + 1) + marker + "</div>" * (MAX_DOM_NODES + 1)).encode()
    with pytest.raises(DescMetadataError) as exc_info:
        parse_desc_publications(DescPublicationSource.NEWS, html)
    message = str(exc_info.value)
    assert "RecursionError" not in message
    assert marker not in message
    assert "<div>" not in message


def test_research_parser_accepts_allowlisted_landing_links_and_rejects_pdf() -> None:
    html = (
        research_card()
        + research_card(title="ACM Study", url="https://dl.acm.org/doi/10.1145/123")
        + research_card(title="PDF Only", url="https://www.researchgate.net/publication/paper.pdf")
        + "<h4 class='elementor-heading-title'><a href='https://evil.test'>Ignore</a></h4>"
    ).encode()
    result = parse_desc_publications(DescPublicationSource.PUBLISHED_RESEARCH, html)
    assert len(result.candidates) == 2
    assert result.rejected_record_count == 1
    assert result.candidates[0].source_published_at is None
    assert result.candidates[0].safe_source_payload == {
        "publication_statement": "Published in Example Journal, July 2026",
        "publishers": "DESC and University",
        "publication_host": "ieeexplore.ieee.org",
        "category": "DESC Published Research",
    }
    assert "pdf" not in repr(result.candidates[0].safe_source_payload).casefold()
    repeated = parse_desc_publications(DescPublicationSource.PUBLISHED_RESEARCH, html)
    assert [item.source_external_id for item in repeated.candidates] == [
        item.source_external_id for item in result.candidates
    ]


@pytest.mark.parametrize(
    "url",
    [
        "https://ieeexplore.ieee.org/document/12345678",
        "https://www.sciencedirect.com/science/article/pii/S123456789",
        "https://www.sciencedirect.com/science/article/abs/pii/S123456789",
        "https://dl.acm.org/doi/10.1145/1234567",
        "https://dl.acm.org/doi/abs/10.1145/1234567",
        "https://www.researchgate.net/publication/12345678",
        "https://www.researchgate.net/publication/12345678_Safe_Title",
    ],
)
def test_research_host_specific_landing_paths_are_accepted(url: str) -> None:
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        research_card(url=url).encode(),
    )
    assert result.candidates[0].canonical_url == url


@pytest.mark.parametrize(
    "canonical_url",
    [
        "https://ieeexplore.ieee.org/document/12345678",
        "https://www.sciencedirect.com/science/article/pii/S123456789",
        "https://dl.acm.org/doi/10.1145/1234567",
        "https://www.researchgate.net/publication/12345678_Safe_Title",
    ],
)
def test_research_trailing_slash_variants_share_canonical_identity(
    canonical_url: str,
) -> None:
    without_slash = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        research_card(url=canonical_url).encode(),
    ).candidates[0]
    with_slash = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        research_card(url=canonical_url + "/").encode(),
    ).candidates[0]

    assert without_slash.canonical_url == canonical_url
    assert with_slash.canonical_url == canonical_url
    assert with_slash.source_external_id == without_slash.source_external_id


def test_research_trailing_slash_variants_collapse_as_one_exact_duplicate() -> None:
    canonical_url = "https://ieeexplore.ieee.org/document/12345678"
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (
            research_card(url=canonical_url)
            + research_card(url=canonical_url + "/")
        ).encode(),
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].canonical_url == canonical_url
    assert result.rejected_record_count == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://dl.acm.org/login",
        "https://www.sciencedirect.com/search",
        "https://ieeexplore.ieee.org/account/login",
        "https://www.researchgate.net/signup",
        "https://www.sciencedirect.com/science/article/pii/S123/pdfft?download=true",
        "https://www.researchgate.net/publication/123/downloadFile/paper",
        "https://ieeexplore.ieee.org/document/123/PdF",
        "https://dl.acm.org/doi/ePdF/10.1145/123",
        "https://www.researchgate.net/publication/123/AtTaChMeNt/file",
        "https://www.sciencedirect.com/science/article/pii/S123?PDF=true",
        "https://www.sciencedirect.com/science/article/pii/S123?file_id=1",
        "https://dl.acm.org/doi/10.1145/123?format=pdf",
        "https://ieeexplore.ieee.org/document/123?export=1",
        "https://ieeexplore.ieee.org:444/document/123",
        "https://ieeexplore.ieee.org/document/",
        "https://ieeexplore.ieee.org/document/abc",
        "https://www.sciencedirect.com/science/article/pii/",
        "https://dl.acm.org/doi/pdf/10.1145/123",
        "https://www.researchgate.net/publication/abc",
        "https://dl.acm.org/%2fdoi/10.1145/123",
        "https://dl.acm.org/doi/%ZZ/123",
        "https://dl.acm.org/doi/../login",
    ],
)
def test_research_arbitrary_and_direct_delivery_paths_fail_closed(url: str) -> None:
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (research_card(title="Good") + research_card(title="Rejected", url=url)).encode(),
    )
    assert [candidate.canonical_title for candidate in result.candidates] == ["Good"]
    assert result.rejected_record_count == 1
    assert DescRejectionCategory.UNSAFE_URL in result.rejection_categories


def test_research_identity_is_url_only_and_exact_duplicates_collapse() -> None:
    url = "https://dl.acm.org/doi/10.1145/7654321"
    card = research_card(url=url)
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (card + card).encode(),
    )
    expected = "desc-published-research:" + sha256(url.encode("utf-8")).hexdigest()
    assert len(result.candidates) == 1
    assert result.candidates[0].source_external_id == expected
    assert result.rejected_record_count == 0


@pytest.mark.parametrize(
    "conflicting_card",
    [
        research_card(title="Changed title"),
        research_card(publishers="Changed publisher"),
        research_card(statement="Changed publication statement"),
    ],
)
def test_research_same_url_conflicts_reject_every_version_order_independently(
    conflicting_card: str,
) -> None:
    original = research_card()
    unrelated = research_card(
        title="Unrelated",
        url="https://www.researchgate.net/publication/987654_Unrelated",
    )
    first = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (original + conflicting_card + unrelated).encode(),
    )
    second = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (conflicting_card + original + unrelated).encode(),
    )
    for result in (first, second):
        assert [candidate.canonical_title for candidate in result.candidates] == ["Unrelated"]
        assert result.rejected_record_count == 2
        assert result.rejection_categories == (
            DescRejectionCategory.DUPLICATE_CONFLICT,
        )
    assert first.candidates == second.candidates


@pytest.mark.parametrize(
    "titles",
    [
        ("Version A", "Version A", "Version B"),
        ("Version A", "Version B", "Version B"),
        ("Version A", "Version A", "Version B", "Version B"),
    ],
)
def test_research_conflict_counts_every_group_container_truthfully(
    titles: tuple[str, ...],
) -> None:
    conflicting_url = "https://ieeexplore.ieee.org/document/12345"
    unrelated = research_card(
        title="Unrelated",
        url="https://www.researchgate.net/publication/987654_Unrelated",
    )

    results = []
    for ordered_titles in (titles, tuple(reversed(titles))):
        conflicting = "".join(
            research_card(title=title, url=conflicting_url)
            for title in ordered_titles
        )
        results.append(
            parse_desc_publications(
                DescPublicationSource.PUBLISHED_RESEARCH,
                (conflicting + unrelated).encode(),
            )
        )

    for result in results:
        assert [candidate.canonical_title for candidate in result.candidates] == [
            "Unrelated"
        ]
        assert result.rejected_record_count == len(titles)
        assert result.rejection_categories == (
            DescRejectionCategory.DUPLICATE_CONFLICT,
        )
    assert results[0].candidates == results[1].candidates


@pytest.mark.parametrize(
    "url",
    [
        "http://ieeexplore.ieee.org/document/1", "https://ieeexplore.ieee.org:443/document/1",
        "https://user@ieeexplore.ieee.org/document/1", "https://evil.ieeexplore.ieee.org/document/1",
        "https://ieeexplore.ieee.org.evil.test/document/1", "https://www.desc.gov.ae/paper/1",
        "https://ieeexplore.ieee.org./document/1", "https://127.0.0.1/document/1",
        "https://[::1]/document/1",
        "https://example.com/paper", "https://dl.acm.org/pdf/1", "https://dl.acm.org/download/1",
        "https://dl.acm.org/doi/%2e%2e/1", "https://dl.acm.org/doi/1#fragment",
        "https://dl.acm.org/doi/1?token=secret", "https://dl.acm.org/wp-content/uploads/a",
        "https://dl.acm.org/doi\\1", "https://dl.acm.org/doi;download/1",
    ],
)
def test_research_url_boundary_rejections_are_counted(url: str) -> None:
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (research_card(title="Good") + research_card(title="Bad", url=url)).encode(),
    )
    assert len(result.candidates) == 1
    assert result.rejected_record_count == 1


@pytest.mark.parametrize(
    "bad_url",
    ["https://[bad/document/1", "https://[::1/document/1"],
)
@pytest.mark.parametrize(
    ("source", "valid_record", "invalid_record"),
    [
        (
            DescPublicationSource.NEWS,
            news_article("good"),
            lambda value: news_article("bad", href=value),
        ),
        (
            DescPublicationSource.PUBLISHED_RESEARCH,
            research_card(title="Good"),
            lambda value: research_card(title="Bad", url=value),
        ),
    ],
)
def test_malformed_url_authorities_are_sanitized_as_unsafe_url(
    bad_url: str,
    source: DescPublicationSource,
    valid_record: str,
    invalid_record,
) -> None:
    result = parse_desc_publications(
        source,
        (valid_record + invalid_record(bad_url)).encode(),
    )

    assert len(result.candidates) == 1
    assert result.rejected_record_count == 1
    assert result.rejection_categories == (DescRejectionCategory.UNSAFE_URL,)
    assert bad_url not in repr(result)


def test_research_missing_or_ambiguous_fields_and_oversized_text_are_rejected() -> None:
    missing = research_card(title="Missing").replace("<p><strong>Publishers:</strong> DESC and University</p>", "")
    ambiguous = research_card(title="Ambiguous").replace("</section>", "<a href='https://dl.acm.org/doi/2'>Visit Publication</a></section>")
    oversized = research_card(title="T" * 501)
    result = parse_desc_publications(
        DescPublicationSource.PUBLISHED_RESEARCH,
        (research_card(title="Good") + missing + ambiguous + oversized).encode(),
    )
    assert len(result.candidates) == 1
    assert result.rejected_record_count == 3


@pytest.mark.parametrize("body", [b"<html>nothing trusted</html>", b"\xff\xfeinvalid"])
def test_empty_or_invalid_encoding_fails_safely(body: bytes) -> None:
    with pytest.raises(DescMetadataError) as exc_info:
        parse_desc_publications(DescPublicationSource.NEWS, body)
    assert "html" not in str(exc_info.value).casefold()
    assert repr(body) not in str(exc_info.value)


def test_pending_approval_opens_no_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    transport = httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(200, content=news_article().encode(), headers={"content-type": "text/html"}))
    client = DescPublicationsClient(DescPublicationSource.NEWS, transport=transport)
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: False)
    with pytest.raises(DescApprovalPendingError):
        client.fetch()
    client.close()
    assert requests == []


def test_timeout_and_transport_configuration_are_closed() -> None:
    with pytest.raises(ValueError):
        DescPublicationsClient(
            DescPublicationSource.NEWS,
            timeout=httpx.Timeout(60.0),
        )
    with pytest.raises(TypeError):
        DescPublicationsClient(
            DescPublicationSource.NEWS,
            transport=httpx.HTTPTransport(),
        )


def test_transport_uses_one_fixed_request_and_safe_client_state(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=news_article().encode(), headers={"content-type": "text/html; charset=utf-8"})
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    client = DescPublicationsClient(DescPublicationSource.NEWS, transport=httpx.MockTransport(respond))
    assert client._client.follow_redirects is False
    assert client._client._trust_env is False
    result = client.fetch()
    client.close()
    assert len(result.candidates) == 1
    assert [str(request.url) for request in requests] == ["https://www.desc.gov.ae/media-hub/news/"]
    assert requests[0].headers["user-agent"] == USER_AGENT
    assert requests[0].headers["accept"] == ACCEPT_HEADER
    assert "cookie" not in requests[0].headers


@pytest.mark.parametrize(
    ("status", "headers", "error"),
    [
        (302, {"content-type": "text/html", "location": "https://www.desc.gov.ae/page/2/"}, DescRedirectError),
        (429, {"content-type": "text/html"}, DescRateLimitError),
        (500, {"content-type": "text/html"}, DescHttpError),
        (200, {"content-type": "application/pdf"}, DescContentTypeError),
        (200, {"content-type": "text/html", "content-length": str(MAX_RESPONSE_BYTES + 1)}, DescResponseTooLargeError),
    ],
)
def test_transport_failures_are_sanitized(monkeypatch: pytest.MonkeyPatch, status: int, headers: dict[str, str], error: type[Exception]) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    transport = httpx.MockTransport(lambda request: httpx.Response(status, headers=headers, content=b"private provider body"))
    with DescPublicationsClient(DescPublicationSource.NEWS, transport=transport) as client:
        with pytest.raises(error) as exc_info:
            client.fetch()
    assert "private" not in str(exc_info.value)


def test_chunked_body_over_limit_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "automated_uae_access_is_approved", lambda slug: True)
    content = b"x" * (MAX_RESPONSE_BYTES + 1)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "text/html"}, content=content))
    with DescPublicationsClient(DescPublicationSource.NEWS, transport=transport) as client:
        with pytest.raises(DescResponseTooLargeError):
            client.fetch()
