import { expect, test, vi } from "vitest";
import { apiFetch } from "@/services/apiClient";
import { buildAuditQuery, fetchAuditEvents } from "@/services/auditApi";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));

test("builds bounded encoded audit filters", () => {
  const query = buildAuditQuery({ action: "auth.login", outcome: "success", correlationId: "11111111-1111-4111-8111-111111111111", limit: 25, offset: 50 });
  expect(query).toContain("action=auth.login");
  expect(query).toContain("offset=50");
  expect(() => buildAuditQuery({ limit: 101 })).toThrow();
});

test("validates safe audit fields", async () => {
  vi.mocked(apiFetch).mockResolvedValue(new Response(JSON.stringify({ items: [{ public_id: "11111111-1111-4111-8111-111111111111", actor_type: "user", actor_ref: "actor", action: "auth.login", target_type: "authentication", target_ref: "session", outcome: "success", correlation_id: null, safe_detail: { operation: "login" }, occurred_at: "2026-08-09T00:00:00Z" }], total: 1, limit: 25, offset: 0 }), { status: 200 }));
  expect((await fetchAuditEvents({ limit: 25, offset: 0 })).status).toBe("success");
});

test("rejects malformed network data", async () => {
  vi.mocked(apiFetch).mockResolvedValue(new Response(JSON.stringify({ items: [{ raw_request_body: "secret" }], total: 1, limit: 25, offset: 0 }), { status: 200 }));
  expect((await fetchAuditEvents({})).status).toBe("error");
});
