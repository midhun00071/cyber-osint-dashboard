import { beforeEach, describe, expect, test, vi } from "vitest";

import {
  buildRunQuery,
  fetchOperationsSummary,
  fetchCycles,
  fetchRun,
  fetchRunEvents,
  fetchRuns,
  fetchSources,
  requestRetry,
} from "@/services/operationsApi";
import { apiFetch } from "@/services/apiClient";
import type { RunFilters } from "@/types/operations";

vi.mock("@/services/apiClient", () => ({ apiFetch: vi.fn() }));
const apiFetchMock = vi.mocked(apiFetch);

const RUN = {
  public_id: "11111111-1111-4111-8111-111111111111",
  cycle_public_id: "22222222-2222-4222-8222-222222222222",
  source_public_id: "33333333-3333-4333-8333-333333333333",
  source_slug: "cisa-kev", source_name: "CISA KEV", trigger_type: "manual", status: "failed",
  attempt_number: 1, retry_of_public_id: null, accepted_at: "2026-08-05T12:00:00Z",
  started_at: "2026-08-05T12:00:01Z", finished_at: "2026-08-05T12:01:00Z",
  duration_seconds: 59, retryable: true, summary_message: "Safe summary.",
  counters: { fetched: 1, created: 0, updated: 0, unchanged: 1, skipped: 0, failed: 0, error_count: 1 },
};

describe("operationsApi", () => {
  beforeEach(() => apiFetchMock.mockReset());

  test("constructs run queries from only fixed allow-listed filter names", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, limit: 50, offset: 25 }), { status: 200 }));
    const filters = {
      sourceSlug: "cisa-kev", status: "failed", triggerType: "manual", retryable: true,
      from: "2026-08-01T00:00:00+04:00", to: "2026-08-02T00:00:00+04:00", limit: 50, offset: 25,
      arbitrary: "must-not-appear",
    } as RunFilters & { arbitrary: string };
    await fetchRuns(filters);
    const path = apiFetchMock.mock.calls[0][0];
    const params = new URLSearchParams(path.split("?", 2)[1]);
    expect([...params.keys()].sort()).toEqual(["from", "limit", "offset", "retryable", "source_slug", "status", "to", "trigger_type"]);
    expect(params.get("source_slug")).toBe("cisa-kev");
    expect(params.get("arbitrary")).toBeNull();
  });

  test("rejects unbounded or timezone-naive run filters before a request", async () => {
    expect(() => buildRunQuery({ limit: 101 })).toThrow(RangeError);
    expect(() => buildRunQuery({ from: "2026-08-01T00:00:00" })).toThrow(TypeError);
    expect(() => buildRunQuery({ from: "2026-01-01T00:00:00Z", to: "2026-08-01T00:00:00Z" })).toThrow(RangeError);
    expect(apiFetchMock).not.toHaveBeenCalled();
  });

  test("uses public run UUIDs for safe detail and event requests", async () => {
    apiFetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify(RUN), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ sequence: 1, event_type: "transition", from_status: "running", to_status: "failed", message: "Safe event.", occurred_at: "2026-08-05T12:01:00Z" }], total: 1, limit: 500, offset: 0 }), { status: 200 }));
    await expect(fetchRun(RUN.public_id)).resolves.toMatchObject({ status: "success" });
    await expect(fetchRunEvents(RUN.public_id)).resolves.toMatchObject({ status: "success" });
    expect(apiFetchMock.mock.calls[0][0]).toBe(`/api/v1/ingestion/runs/${RUN.public_id}`);
    expect(apiFetchMock.mock.calls[1][0]).toBe(`/api/v1/ingestion/runs/${RUN.public_id}/events?limit=500&offset=0`);
  });

  test("accepts explicit null cycle ids in mixed run lists", async () => {
    const cycleLessRun = {
      ...RUN,
      public_id: "77777777-7777-4777-8777-777777777777",
      cycle_public_id: null,
    };
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({
      items: [RUN, cycleLessRun], total: 2, limit: 25, offset: 0,
    }), { status: 200 }));

    await expect(fetchRuns()).resolves.toEqual({
      status: "success",
      data: { items: [RUN, cycleLessRun], total: 2, limit: 25, offset: 0 },
    });
  });

  test("rejects missing or invalid cycle ids in run payloads", async () => {
    const missingCycle = { ...RUN } as Record<string, unknown>;
    delete missingCycle.cycle_public_id;
    apiFetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [missingCycle], total: 1, limit: 25, offset: 0,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{ ...RUN, cycle_public_id: 42 }], total: 1, limit: 25, offset: 0,
      }), { status: 200 }));

    await expect(fetchRuns()).resolves.toEqual({ status: "error" });
    await expect(fetchRuns()).resolves.toEqual({ status: "error" });
  });

  test("does not invent a retry idempotency header", async () => {
    apiFetchMock.mockResolvedValue(new Response("{}", { status: 202, headers: { "Content-Type": "application/json" } }));
    await requestRetry("run-id");
    expect(apiFetchMock).toHaveBeenCalledWith("/api/v1/ingestion/runs/run-id/retry", { method: "POST", body: "{}" });
  });

  test("rejects malformed source payloads", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({ items: [{ slug: "missing-fields" }], total: 1, limit: 100, offset: 0 }), { status: 200 }));
    await expect(fetchSources()).resolves.toEqual({ status: "error" });
  });

  test("accepts a null latest run and preserves it in a complete source payload", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({
      items: [{
        public_id: "11111111-1111-4111-8111-111111111111",
        slug: "cisa-kev",
        name: "CISA KEV",
        source_type: "feed",
        content_type: "application/json",
        access_class: "public",
        policy_state: "approved",
        operator_state: "enabled",
        effective_state: "available",
        credential_required: false,
        credential_configured: true,
        execution_available: true,
        freshness: "fresh",
        progress: {
          kind: "none",
          version: null,
          committed_at: null,
          fingerprint: null,
        },
        latest_run: null,
        quota_state: null,
        backoff_until: null,
        next_scheduled_at: null,
        available_actions: ["manual_run"],
      }],
      total: 1,
      limit: 100,
      offset: 0,
    }), { status: 200 }));

    await expect(fetchSources()).resolves.toEqual({
      status: "success",
      data: {
        items: [{
          public_id: "11111111-1111-4111-8111-111111111111",
          slug: "cisa-kev",
          name: "CISA KEV",
          source_type: "feed",
          content_type: "application/json",
          access_class: "public",
          policy_state: "approved",
          operator_state: "enabled",
          effective_state: "available",
          credential_required: false,
          credential_configured: true,
          execution_available: true,
          freshness: "fresh",
          progress: {
            kind: "none",
            version: null,
            committed_at: null,
            fingerprint: null,
          },
          latest_run: null,
          quota_state: null,
          backoff_until: null,
          next_scheduled_at: null,
          available_actions: ["manual_run"],
        }],
        total: 1,
        limit: 100,
        offset: 0,
      },
    });
  });

  test("rejects malformed non-null latest run objects", async () => {
    apiFetchMock.mockResolvedValue(new Response(JSON.stringify({
      items: [{
        public_id: "11111111-1111-4111-8111-111111111111",
        slug: "cisa-kev",
        name: "CISA KEV",
        source_type: "feed",
        content_type: "application/json",
        access_class: "public",
        policy_state: "approved",
        operator_state: "enabled",
        effective_state: "available",
        credential_required: false,
        credential_configured: true,
        execution_available: true,
        freshness: "fresh",
        progress: {
          kind: "none",
          version: null,
          committed_at: null,
          fingerprint: null,
        },
        latest_run: {
          public_id: "22222222-2222-4222-8222-222222222222",
          status: "success",
          trigger_type: "manual",
          attempt_number: 1,
          started_at: "2026-08-05T12:00:00Z",
        },
        quota_state: null,
        backoff_until: null,
        next_scheduled_at: null,
        available_actions: ["manual_run"],
      }],
      total: 1,
      limit: 100,
      offset: 0,
    }), { status: 200 }));

    await expect(fetchSources()).resolves.toEqual({ status: "error" });
  });

  test("rejects extra fields in allow-listed operations payloads", async () => {
    apiFetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{
          public_id: "11111111-1111-4111-8111-111111111111",
          slug: "cisa-kev",
          name: "CISA KEV",
          source_type: "feed",
          content_type: "application/json",
          access_class: "public",
          policy_state: "approved",
          operator_state: "enabled",
          effective_state: "available",
          credential_required: false,
          credential_configured: true,
          execution_available: true,
          freshness: "fresh",
          progress: {
            kind: "checkpoint",
            version: 1,
            committed_at: "2026-08-05T12:00:00Z",
            fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            checkpoint_value: 7,
          },
          latest_run: {
            public_id: "22222222-2222-4222-8222-222222222222",
            status: "success",
            trigger_type: "manual",
            attempt_number: 1,
            started_at: "2026-08-05T12:00:00Z",
            finished_at: null,
            credential_reference_id: "credential-ref",
          },
          quota_state: null,
          backoff_until: null,
          next_scheduled_at: null,
          available_actions: ["manual_run"],
          provider_payload: {},
        }],
        total: 1,
        limit: 100,
        offset: 0,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{
          public_id: "33333333-3333-4333-8333-333333333333",
          trigger_type: "manual",
          status: "complete",
          started_at: "2026-08-05T12:00:00Z",
          finished_at: null,
          duration_seconds: null,
          sources_expected: 1,
          sources_started: 1,
          sources_completed: 1,
          sources_successful: 1,
          sources_non_successful: 0,
          summary_message: null,
          provider_payload: {},
        }],
        total: 1,
        limit: 25,
        offset: 0,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        public_id: "44444444-4444-4444-8444-444444444444",
        cycle_public_id: "55555555-5555-4555-8555-555555555555",
        source_public_id: "66666666-6666-4666-8666-666666666666",
        source_slug: "cisa-kev",
        source_name: "CISA KEV",
        trigger_type: "manual",
        status: "failed",
        attempt_number: 1,
        retry_of_public_id: null,
        accepted_at: "2026-08-05T12:00:00Z",
        started_at: "2026-08-05T12:00:01Z",
        finished_at: "2026-08-05T12:01:00Z",
        duration_seconds: 59,
        retryable: true,
        summary_message: "Safe summary.",
        counters: {
          fetched: 1,
          created: 0,
          updated: 0,
          unchanged: 1,
          skipped: 0,
          failed: 0,
          error_count: 1,
          raw_error: "not-allowed",
        },
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{
          sequence: 1,
          event_type: "transition",
          from_status: "running",
          to_status: "failed",
          message: "Safe event.",
          occurred_at: "2026-08-05T12:01:00Z",
          raw_error: "not-allowed",
        }],
        total: 1,
        limit: 500,
        offset: 0,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        generated_at: "2026-08-05T12:00:00Z",
        deployment_state: "available",
        configured_handler_count: 1,
        active_cycle_count: 1,
        active_run_count: 1,
        source_attention_count: 0,
        run_counts_by_status: { success: 1 },
        latest_cycle: {
          public_id: "33333333-3333-4333-8333-333333333333",
          trigger_type: "manual",
          status: "complete",
          started_at: "2026-08-05T12:00:00Z",
          finished_at: null,
          duration_seconds: null,
          sources_expected: 1,
          sources_started: 1,
          sources_completed: 1,
          sources_successful: 1,
          sources_non_successful: 0,
          summary_message: null,
          provider_payload: {},
        },
        raw_error: "not-allowed",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [],
        total: 0,
        limit: 25,
        offset: 0,
        raw_error: "not-allowed",
      }), { status: 200 }));

    await expect(fetchSources()).resolves.toEqual({ status: "error" });
    await expect(fetchCycles()).resolves.toEqual({ status: "error" });
    await expect(fetchRun("44444444-4444-4444-8444-444444444444")).resolves.toEqual({ status: "error" });
    await expect(fetchRunEvents("44444444-4444-4444-8444-444444444444")).resolves.toEqual({ status: "error" });
    await expect(fetchOperationsSummary()).resolves.toEqual({ status: "error" });
    await expect(fetchRuns()).resolves.toEqual({ status: "error" });
  });
});
