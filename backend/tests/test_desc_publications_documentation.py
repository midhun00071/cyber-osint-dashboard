from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCS = PROJECT_ROOT / "docs"


def text(name: str) -> str:
    return " ".join((DOCS / name).read_text(encoding="utf-8").split())


def test_desc_publications_document_has_complete_disabled_contract() -> None:
    document = text("desc-publications.md")
    required = (
        "B5-04 implements fixture-tested metadata collectors",
        "`https://www.desc.gov.ae/media-hub/news/`",
        "`https://www.desc.gov.ae/research-innovation/published-research/`",
        "at most one GET",
        "no pagination",
        "`trust_env=False`",
        "2 MiB",
        "50 parsed records",
        "`ieeexplore.ieee.org`",
        "`www.sciencedirect.com`",
        "`dl.acm.org`",
        "`www.researchgate.net`",
        "They are never request targets",
        "`enabled: false`",
        "No live DESC request was made",
        "B5-02 and B5-03 remain deferred",
        "Arbitrary paths on an allow-listed host are rejected",
        "`/document/<1-20-digit-id>`",
        "`/science/article/pii/<safe-pii>`",
        "`/doi/10.<registrant>/<safe-suffix>`",
        "`/publication/<numeric-id>`",
        "download-related query keys",
        "They are never request targets",
        "SHA-256 digest of the already validated canonical publication URL only",
        "every conflicting card is rejected",
        "Exact duplicate cards collapse deterministically",
        "before parsing and deduplication",
        "Overflow contributes to rejected-record counters",
        "capped results are partial and cannot advance progress",
        "iterative bounded walks",
        "`RecursionError`",
        "Malformed counters, categories, candidates, cap flags, or page counts",
        "Optional trailing slashes are removed after strict path validation",
        "slash variants cannot create separate identities",
        "every source container in that conflicting identity is rejected",
        "Malformed URL authorities receive a sanitized `unsafe_url` classification",
    )
    for phrase in required:
        assert phrase in document


def test_all_source_documents_preserve_pending_activation_and_pdf_prohibition() -> None:
    documents = tuple(
        text(name)
        for name in (
            "data-sources.md",
            "source-assessment-matrix.md",
            "source-integration-policy.md",
            "uae-source-governance.md",
        )
    )
    for document in documents:
        assert "`desc-news`" in document
        assert "`desc-published-research`" in document
        assert "disabled" in document.casefold()
        assert "pending" in document.casefold()
    combined = " ".join(documents).casefold()
    assert "direct pdf" in combined or "direct-pdf" in combined
    assert "no live" in combined
