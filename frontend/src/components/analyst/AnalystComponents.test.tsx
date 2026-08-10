import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { IndicatorSearch } from "@/components/analyst/IndicatorSearch";
import { ItemProvenancePanel } from "@/components/analyst/ItemProvenancePanel";
import { ThreatMetadataList } from "@/components/analyst/ThreatMetadataList";
import { UaeIntelligenceList } from "@/components/analyst/UaeIntelligenceList";
import { fetchIndicators, fetchItemProvenance, fetchThreatEntities, fetchUaeIntelligence } from "@/services/analystApi";
import { fetchSources } from "@/services/operationsApi";

vi.mock("@/services/analystApi", () => ({ fetchIndicators: vi.fn(), fetchItemProvenance: vi.fn(), fetchThreatEntities: vi.fn(), fetchUaeIntelligence: vi.fn() }));
vi.mock("@/services/operationsApi", () => ({ fetchSources: vi.fn() }));

const indicatorsMock = vi.mocked(fetchIndicators);
const provenanceMock = vi.mocked(fetchItemProvenance);
const threatMock = vi.mocked(fetchThreatEntities);
const uaeMock = vi.mocked(fetchUaeIntelligence);
const sourcesMock = vi.mocked(fetchSources);

const threat = (sourceUrl = "https://attack.mitre.org/campaigns/C0001/") => ({ public_id: "11111111-1111-4111-8111-111111111111", entity_type: "campaign" as const, name: "Synthetic defensive campaign", attack_id: null, aliases: ["Example alias"], confidence: 0.8, source_slug: "mitre-attack", source_name: "MITRE ATT&CK", source_url: sourceUrl, content_sha256: "a".repeat(64), stix_created_at: "2026-01-01T00:00:00Z", stix_modified_at: "2026-01-02T00:00:00Z", revoked: false });
const indicator = () => ({ public_id: "22222222-2222-4222-8222-222222222222", observable_type: "domain" as const, normalized_value: "example.test", hash_algorithm: null, status: "active" as const, confidence: 0.8, context_summary: "Synthetic context", first_seen_at: null, last_seen_at: null, expires_at: null, provenance_count: 2, publication_count: 3 });
const uaeItem = (sourceUrl = "https://tdra.gov.ae/example") => ({ public_id: "33333333-3333-4333-8333-333333333333", title: "Dubai defensive notice", summary: "A text mention only.", item_type: "security_advisory", cve_id: null, severity: null, source_slug: "ae-cert", source_name: "TDRA / aeCERT", source_url: sourceUrl, published_at: null, modified_at: null, collected_at: "2026-08-08T00:00:00Z", last_seen_at: "2026-08-08T00:00:00Z", geographic_scope: "uae", relevance_status: "possible", relevance_label: "Potential UAE relevance" as const, relevance_confidence: 0.55, relevance_reason: "Potential UAE relevance from a Dubai mention; no attribution asserted.", relevance_method: "automatic", classification_tags: [{ kind: "emirate" as const, slug: "uae-emirate-dubai", label: "Dubai", confidence: 0.7, evidence: "Normalized text mentions Dubai." }] });
const source = (state: "disabled" | "never" | "fresh") => ({ public_id: "44444444-4444-4444-8444-444444444444", slug: "ae-cert", name: "TDRA / aeCERT", source_type: "rss", content_type: "application/rss+xml", access_class: "public" as const, policy_state: "approved" as const, operator_state: state === "disabled" ? "disabled" as const : "enabled" as const, effective_state: state === "disabled" ? "disabled" as const : "enabled" as const, credential_required: false, credential_configured: true, execution_available: state !== "disabled", freshness: state === "never" ? "never" as const : "fresh" as const, progress: { kind: "none" as const, version: null, committed_at: null, fingerprint: null }, latest_run: null, quota_state: null, backoff_until: null, next_scheduled_at: null, available_actions: [] });

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }

describe("C08 analyst components", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    indicatorsMock.mockReset(); provenanceMock.mockReset(); threatMock.mockReset(); uaeMock.mockReset(); sourcesMock.mockReset();
    sourcesMock.mockResolvedValue({ status: "success", data: { items: [], total: 0, limit: 100, offset: 0 } });
  });

  test("ThreatMetadataList covers loading, success, pagination, and safe links", async () => {
    const pending = deferred<Awaited<ReturnType<typeof fetchThreatEntities>>>();
    threatMock.mockReturnValueOnce(pending.promise).mockResolvedValue({ status: "success", data: { total: 26, limit: 25, offset: 25, items: [threat()] } });
    render(<ThreatMetadataList />);
    expect(screen.getByText("Loading stored threat metadata")).toBeVisible();
    pending.resolve({ status: "success", data: { total: 26, limit: 25, offset: 0, items: [threat()] } });
    expect(await screen.findByRole("heading", { name: "Synthetic defensive campaign" })).toBeVisible();
    expect(screen.getByText("Aliases: Example alias")).toBeVisible();
    const link = screen.getByRole("link", { name: "Open source" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/campaigns/C0001/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(threatMock).toHaveBeenLastCalledWith("", 25, expect.any(AbortSignal)));
  });

  test("ThreatMetadataList covers empty, error, and unsafe-link suppression", async () => {
    threatMock.mockResolvedValueOnce({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    const { unmount } = render(<ThreatMetadataList />);
    expect(await screen.findByText("No threat metadata found")).toBeVisible();
    unmount();
    threatMock.mockResolvedValueOnce({ status: "error" });
    const errorView = render(<ThreatMetadataList />);
    expect(await screen.findByText("Threat metadata unavailable")).toBeVisible();
    errorView.unmount();
    threatMock.mockResolvedValueOnce({ status: "success", data: { total: 1, limit: 25, offset: 0, items: [threat("javascript:alert(1)")] } });
    render(<ThreatMetadataList />);
    expect(await screen.findByText("Synthetic defensive campaign")).toBeVisible();
    expect(screen.queryByRole("link", { name: "Open source" })).not.toBeInTheDocument();
    expect(screen.getByText("Open source")).toHaveAttribute("aria-disabled", "true");
  });

  test("UaeIntelligenceList covers loading, wording, disabled state, filtering, pagination, and safe link", async () => {
    const pending = deferred<Awaited<ReturnType<typeof fetchUaeIntelligence>>>();
    sourcesMock.mockResolvedValue({ status: "success", data: { total: 1, limit: 100, offset: 0, items: [source("disabled")] } });
    uaeMock.mockReturnValueOnce(pending.promise).mockResolvedValue({ status: "success", data: { total: 26, limit: 25, offset: 0, items: [uaeItem()] } });
    render(<UaeIntelligenceList />);
    expect(screen.getByText("Loading UAE intelligence")).toBeVisible();
    expect(screen.getByText(/Approved UAE authority evidence can automatically establish direct UAE evidence/)).toBeVisible();
    expect(screen.getByText(/Structured UAE scope is potential relevance, not automatic direct evidence/)).toBeVisible();
    expect(screen.getByText(/Protected reviewed or source-declared classification may remain/)).toBeVisible();
    pending.resolve({ status: "success", data: { total: 26, limit: 25, offset: 0, items: [uaeItem()] } });
    expect(await screen.findByText("Disabled")).toBeVisible();
    expect(screen.getByRole("link", { name: "Open source" })).toHaveAttribute("rel", "noopener noreferrer");
    fireEvent.change(screen.getByRole("combobox", { name: "Evidence category" }), { target: { value: "potential" } });
    await waitFor(() => expect(uaeMock).toHaveBeenLastCalledWith("potential", "", 0, expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(uaeMock).toHaveBeenLastCalledWith("potential", "", 25, expect.any(AbortSignal)));
  });

  test("UaeIntelligenceList distinguishes never-run, unavailable, empty, error, and unsafe links", async () => {
    sourcesMock.mockResolvedValueOnce({ status: "success", data: { total: 1, limit: 100, offset: 0, items: [source("never")] } });
    uaeMock.mockResolvedValueOnce({ status: "success", data: { total: 1, limit: 25, offset: 0, items: [uaeItem("javascript:alert(1)")] } });
    const neverRun = render(<UaeIntelligenceList />);
    expect(await screen.findByText("Never run")).toBeVisible();
    expect(screen.queryByRole("link", { name: "Open source" })).not.toBeInTheDocument();
    neverRun.unmount();
    uaeMock.mockResolvedValueOnce({ status: "success", data: { total: 1, limit: 25, offset: 0, items: [uaeItem()] } });
    const unavailable = render(<UaeIntelligenceList />);
    expect(await screen.findByText("State unavailable")).toBeVisible();
    unavailable.unmount();
    uaeMock.mockResolvedValueOnce({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    const empty = render(<UaeIntelligenceList />);
    expect(await screen.findByText("No matching UAE intelligence")).toBeVisible();
    empty.unmount();
    uaeMock.mockResolvedValueOnce({ status: "error" });
    render(<UaeIntelligenceList />);
    expect(await screen.findByText("UAE intelligence unavailable")).toBeVisible();
  });

  test("IndicatorSearch performs no pre-search request and covers loading, success, and pagination", async () => {
    const pending = deferred<Awaited<ReturnType<typeof fetchIndicators>>>();
    indicatorsMock.mockReturnValueOnce(pending.promise).mockResolvedValue({ status: "success", data: { total: 26, limit: 25, offset: 25, items: [indicator()] } });
    render(<IndicatorSearch />);
    expect(screen.getByText("Enter an indicator to search")).toBeVisible();
    expect(indicatorsMock).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    expect(await screen.findByText("Searching stored indicators")).toBeVisible();
    pending.resolve({ status: "success", data: { total: 26, limit: 25, offset: 0, items: [indicator()] } });
    expect(await screen.findByText("example.test")).toBeVisible();
    expect(screen.getByText("2")).toBeVisible();
    expect(screen.getByText("3")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(indicatorsMock).toHaveBeenLastCalledWith("example.test", 25, expect.any(AbortSignal)));
  });

  test("IndicatorSearch covers empty and error states", async () => {
    indicatorsMock.mockResolvedValueOnce({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    const empty = render(<IndicatorSearch />);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "empty.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    expect(await screen.findByText("No stored indicators match")).toBeVisible();
    empty.unmount();
    indicatorsMock.mockResolvedValueOnce({ status: "error" });
    render(<IndicatorSearch />);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "error.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    expect(await screen.findByText("Indicator search unavailable")).toBeVisible();
  });

  test("UaeIntelligenceList restores list state and links details back to that context", async () => {
    window.history.replaceState({}, "", "/uae-intelligence?q=dubai&relevance=potential&offset=25");
    uaeMock.mockResolvedValue({ status: "success", data: { total: 26, limit: 25, offset: 25, items: [uaeItem()] } });
    render(<UaeIntelligenceList />);
    await waitFor(() => expect(uaeMock).toHaveBeenCalledWith("potential", "dubai", 25, expect.any(AbortSignal)));
    const detail = await screen.findByRole("link", { name: "Dubai defensive notice" });
    expect(decodeURIComponent(detail.getAttribute("href") ?? "")).toContain("returnTo=/uae-intelligence?q=dubai&relevance=potential&offset=25");
    expect(screen.getAllByText("security advisory")).toHaveLength(2);
    expect(screen.getByText("UAE")).toBeVisible();
    window.history.replaceState({}, "", "/");
  });

  test("IndicatorSearch blocks obviously malformed values without any request", async () => {
    render(<IndicatorSearch />);
    const input = screen.getByRole("searchbox", { name: "Indicator value" });
    expect(input).toHaveAttribute("id", "indicator-value");
    expect(input).toHaveAttribute("name", "indicator_value");
    fireEvent.change(input, { target: { value: "999.1.2.3" } });
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("valid IPv4 address");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(indicatorsMock).not.toHaveBeenCalled();
  });

  test("IndicatorSearch permits and submits a 128-character hexadecimal hash", async () => {
    const hash = "a".repeat(128);
    indicatorsMock.mockResolvedValue({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    render(<IndicatorSearch />);
    const input = screen.getByRole("searchbox", { name: "Indicator value" });
    expect(input).toHaveAttribute("maxlength", "128");
    fireEvent.change(input, { target: { value: hash } });
    expect(input).toHaveValue(hash);
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    await waitFor(() => expect(indicatorsMock).toHaveBeenCalledWith(hash, 0, expect.any(AbortSignal)));
  });

  test("IndicatorSearch accepts supported values for offline lookup", async () => {
    indicatorsMock.mockResolvedValue({ status: "success", data: { total: 0, limit: 25, offset: 0, items: [] } });
    render(<IndicatorSearch />);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "2001:db8::1" } });
    fireEvent.click(screen.getByRole("button", { name: "Search stored indicators" }));
    await waitFor(() => expect(indicatorsMock).toHaveBeenCalledWith("2001:db8::1", 0, expect.any(AbortSignal)));
  });

  test("ItemProvenancePanel covers loading, success, safe links, and bounded evidence", async () => {
    const pending = deferred<Awaited<ReturnType<typeof fetchItemProvenance>>>();
    provenanceMock.mockReturnValue(pending.promise);
    render(<ItemProvenancePanel publicId="55555555-5555-4555-8555-555555555555" />);
    expect(screen.getByText(/Loading provenance evidence/)).toBeVisible();
    const sources = Array.from({ length: 26 }, (_, index) => ({ source_slug: `source-${index + 1}`, source_name: `Source ${index + 1}`, source_url: "https://example.test/evidence", content_sha256: "a".repeat(64), published_at: null, modified_at: null, collected_at: "2026-08-08T00:00:00Z", first_seen_at: "2026-08-08T00:00:00Z", last_seen_at: "2026-08-08T00:00:00Z", import_runs: Array.from({ length: 21 }, (__, run) => ({ public_id: `run-${run + 1}`, action: `action-${run + 1}`, status: "success", started_at: "2026-08-08T00:00:00Z", completed_at: null, processed_at: "2026-08-08T00:00:00Z" })) }));
    const classification_tags = Array.from({ length: 17 }, (_, index) => ({ kind: "sector" as const, slug: `uae-sector-${index + 1}`, label: `Sector ${index + 1}`, confidence: 0.8, evidence: "Controlled evidence" }));
    const indicators = Array.from({ length: 101 }, (_, index) => ({ public_id: `indicator-${index + 1}`, observable_type: "domain", normalized_value: `indicator-${index + 1}.example`, hash_algorithm: null, status: "active", confidence: 0.8, context_summary: null, first_observed_at: "2026-08-08T00:00:00Z", last_observed_at: "2026-08-08T00:00:00Z" }));
    pending.resolve({ status: "success", data: { item_public_id: "55555555-5555-4555-8555-555555555555", sources, classification_tags, indicators } });
    expect(await screen.findByRole("heading", { name: "Provenance and relationships" })).toBeVisible();
    expect(screen.getAllByRole("link", { name: "Open source evidence" })).toHaveLength(25);
    expect(screen.getAllByRole("link", { name: "Open source evidence" })[0]).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByText("Source 26")).not.toBeInTheDocument();
    expect(screen.queryByText(/action-21/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Sector 17/)).not.toBeInTheDocument();
    expect(screen.queryByText(/indicator-101\.example/)).not.toBeInTheDocument();
  });

  test("ItemProvenancePanel covers not-found, error, and unsafe links", async () => {
    provenanceMock.mockResolvedValueOnce({ status: "not_found" });
    const missing = render(<ItemProvenancePanel publicId="missing" />);
    expect(await screen.findByText("No provenance record was found.")).toBeVisible();
    missing.unmount();
    provenanceMock.mockResolvedValueOnce({ status: "error" });
    const error = render(<ItemProvenancePanel publicId="error" />);
    expect(await screen.findByText("Provenance evidence is temporarily unavailable.")).toBeVisible();
    error.unmount();
    provenanceMock.mockResolvedValueOnce({ status: "success", data: { item_public_id: "unsafe", sources: [{ source_slug: "unsafe", source_name: "Unsafe source", source_url: "javascript:alert(1)", content_sha256: null, published_at: null, modified_at: null, collected_at: "2026-08-08T00:00:00Z", first_seen_at: "2026-08-08T00:00:00Z", last_seen_at: "2026-08-08T00:00:00Z", import_runs: [] }], classification_tags: [], indicators: [] } });
    render(<ItemProvenancePanel publicId="unsafe" />);
    expect(await screen.findByText("Unsafe source")).toBeVisible();
    expect(screen.queryByRole("link", { name: "Open source evidence" })).not.toBeInTheDocument();
  });
});
