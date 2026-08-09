import { expect, test, vi } from "vitest";
import { apiFetch } from "@/services/apiClient";
import { fetchSystemHealth } from "@/services/systemHealthApi";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));

test("accepts every truthful health vocabulary state and deployment identity", async () => {
  const names = ["backend", "database", "prefect_server", "prefect_worker", "ingestion_operations", "source_freshness", "storage", "deployment_identity"];
  const states = ["healthy", "degraded", "unhealthy", "stale", "disabled", "unknown", "healthy", "healthy"];
  vi.mocked(apiFetch).mockResolvedValue(new Response(JSON.stringify({ status: "degraded", generated_at: "2026-08-09T00:00:00Z", version: "1.2.3", commit_sha: "a".repeat(40), components: names.map((name, index) => ({ name, status: states[index], summary: "Safe state.", observations: {} })) }), { status: 200 }));
  const result = await fetchSystemHealth();
  expect(result.status).toBe("success");
  if (result.status === "success") expect(result.data.commit_sha).toBe("a".repeat(40));
});

test("fails closed on malformed health data", async () => {
  vi.mocked(apiFetch).mockResolvedValue(new Response(JSON.stringify({ status: "green", components: [] }), { status: 200 }));
  expect((await fetchSystemHealth()).status).toBe("error");
});
