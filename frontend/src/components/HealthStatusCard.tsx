"use client";

import { useEffect, useState } from "react";

import { API_BASE_URL } from "@/services/apiClient";
import type { HealthResponse } from "@/types/health";

type RequestState =
  | { status: "loading" }
  | { status: "success"; data: HealthResponse }
  | { status: "error" };

function isHealthResponse(value: unknown): value is HealthResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as Record<string, unknown>;

  return (
    typeof response.status === "string" &&
    typeof response.service === "string" &&
    typeof response.environment === "string" &&
    typeof response.timestamp === "string"
  );
}

export function HealthStatusCard() {
  const [requestState, setRequestState] = useState<RequestState>({
    status: "loading",
  });

  useEffect(() => {
    const controller = new AbortController();

    async function checkHealth() {
      try {
        const response = await fetch(`${API_BASE_URL}/api/health`, {
          cache: "no-store",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error("Health request failed");
        }

        const data: unknown = await response.json();

        if (!isHealthResponse(data)) {
          throw new Error("Unexpected health response");
        }

        setRequestState({ status: "success", data });
      } catch (error: unknown) {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }

        setRequestState({ status: "error" });
      }
    }

    void checkHealth();

    return () => controller.abort();
  }, []);

  if (requestState.status === "loading") {
    return (
      <div className="healthCard" aria-live="polite" aria-busy="true">
        <span className="statusIndicator statusLoading" aria-hidden="true" />
        <div>
          <p className="healthLabel">Backend API</p>
          <h3>Checking service availability…</h3>
          <p>Waiting for a response from the health endpoint.</p>
        </div>
      </div>
    );
  }

  if (requestState.status === "error") {
    return (
      <div className="healthCard healthError" role="status">
        <span className="statusIndicator statusError" aria-hidden="true" />
        <div>
          <p className="healthLabel">Backend API</p>
          <h3>Service unavailable</h3>
          <p>
            The dashboard could not confirm backend availability. Check that the
            API is running and try again shortly.
          </p>
        </div>
      </div>
    );
  }

  const { data } = requestState;
  const checkedAt = new Date(data.timestamp);
  const formattedTime = Number.isNaN(checkedAt.getTime())
    ? "Recently"
    : checkedAt.toLocaleString();

  return (
    <div className="healthCard healthSuccess" role="status">
      <span className="statusIndicator statusSuccess" aria-hidden="true" />
      <div className="healthContent">
        <div>
          <p className="healthLabel">Backend API</p>
          <h3>{data.service} is operational</h3>
          <p>Health check completed successfully.</p>
        </div>
        <dl className="healthMetadata">
          <div>
            <dt>Environment</dt>
            <dd>{data.environment}</dd>
          </div>
          <div>
            <dt>Checked</dt>
            <dd>{formattedTime}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
