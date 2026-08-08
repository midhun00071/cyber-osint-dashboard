import { beforeEach, describe, expect, test, vi } from "vitest";

import { fetchIndicators, fetchItemProvenance, fetchThreatEntities, fetchUaeIntelligence } from "@/services/analystApi";
import { apiFetch } from "@/services/apiClient";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

const list = (item: object) => ({ items: [item], total: 1, limit: 25, offset: 0 });

describe("analystApi", () => {
  beforeEach(() => apiFetchMock.mockReset());

  test("builds only bounded allow-listed threat and indicator searches", async () => {
    apiFetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify(list({ public_id: "1", entity_type: "campaign", name: "Campaign", attack_id: null, aliases: [], confidence: null, source_slug: "source", source_name: "Source", source_url: "https://example.test/item", content_sha256: null, stix_created_at: "2026-01-01T00:00:00Z", stix_modified_at: "2026-01-01T00:00:00Z", revoked: false })), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(list({ public_id: "2", observable_type: "domain", normalized_value: "example.test", hash_algorithm: null, status: "active", confidence: 0.8, context_summary: null, first_seen_at: null, last_seen_at: null, expires_at: null, provenance_count: 1, publication_count: 1 })), { status: 200 }));
    await expect(fetchThreatEntities("  ATT&CK  ", 0)).resolves.toMatchObject({ status: "success" });
    await expect(fetchIndicators(" example.test ", 0)).resolves.toMatchObject({ status: "success" });
    expect(apiFetchMock.mock.calls[0][0]).toBe("/api/v1/analysis/threat-entities?limit=25&offset=0&q=ATT%26CK");
    expect(apiFetchMock.mock.calls[1][0]).toBe("/api/v1/analysis/indicators?limit=25&offset=0&status=active&q=example.test");
  });

  test("rejects malformed and unexpectedly shaped list payloads", async () => {
    apiFetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ public_id: "missing-fields" }], total: 1, limit: 25, offset: 0 }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [], total: -1, limit: 25, offset: 0 }), { status: 200 }));
    await expect(fetchIndicators("test", 0)).resolves.toEqual({ status: "error" });
    await expect(fetchUaeIntelligence("direct", "", 0)).resolves.toEqual({ status: "error" });
  });

  test("uses the public item UUID for provenance and handles not found", async () => {
    apiFetchMock.mockResolvedValue(new Response("{}", { status: 404 }));
    await expect(fetchItemProvenance("11111111-1111-4111-8111-111111111111")).resolves.toEqual({ status: "not_found" });
    expect(apiFetchMock).toHaveBeenCalledWith("/api/v1/analysis/items/11111111-1111-4111-8111-111111111111/provenance", { signal: undefined });
  });
});
