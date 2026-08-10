import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { VulnerabilitiesTable } from "@/components/dashboard/VulnerabilitiesTable";
import { fetchVulnerabilities } from "@/services/vulnerabilityApi";
import { makeVulnerability, makeVulnerabilityList } from "@/test/fixtures";
import type { VulnerabilityListResult } from "@/types/vulnerability";

const { useSearchParamsMock } = vi.hoisted(() => ({ useSearchParamsMock: vi.fn() }));

vi.mock("next/navigation", () => ({ useSearchParams: useSearchParamsMock }));
vi.mock("@/services/vulnerabilityApi", () => ({
  fetchVulnerabilities: vi.fn(),
}));

const fetchVulnerabilitiesMock = vi.mocked(fetchVulnerabilities);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function pendingUntilAbort(signal?: AbortSignal): Promise<VulnerabilityListResult> {
  return new Promise((_resolve, reject) => {
    signal?.addEventListener(
      "abort",
      () => reject(new DOMException("Aborted", "AbortError")),
      { once: true },
    );
  });
}

describe("VulnerabilitiesTable", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/vulnerabilities");
    useSearchParamsMock.mockImplementation(() => new URLSearchParams(window.location.search));
    fetchVulnerabilitiesMock.mockResolvedValue({
      status: "success",
      data: makeVulnerabilityList(),
    });
  });

  test("shows an accessible loading state with disabled pagination", () => {
    fetchVulnerabilitiesMock.mockImplementation((_filters, signal) =>
      pendingUntilAbort(signal),
    );
    render(<VulnerabilitiesTable />);

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  test("renders table headers, representative data, navigation, and text safely", async () => {
    const markupTitle = "<svg onload=alert(1)>";
    fetchVulnerabilitiesMock.mockResolvedValue({
      status: "success",
      data: makeVulnerabilityList({
        items: [makeVulnerability({ title: markupTitle })],
      }),
    });
    render(<VulnerabilitiesTable />);

    const cveLink = await screen.findByRole("link", { name: "CVE-2026-12345" });
    expect(cveLink).toHaveAttribute(
      "href",
      "/vulnerabilities/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee?returnTo=%2Fvulnerabilities",
    );
    expect(screen.getByText(markupTitle)).toBeVisible();
    expect(document.querySelector("svg")).toBeNull();
    expect(within(screen.getByRole("table")).getByText("Critical")).toBeVisible();
    expect(screen.getByText("9.8 / 3.1")).toBeVisible();
    expect(screen.getByText("42.00% / P91.0")).toBeVisible();
    expect(screen.getByText("KEV listed")).toBeVisible();
    expect(screen.getByText("Synthetic CVE Source")).toBeVisible();
    for (const name of ["CVE", "Severity", "CVSS", "EPSS", "KEV", "Published", "Source"]) {
      expect(screen.getByRole("columnheader", { name })).toBeVisible();
    }
  });

  test("shows All years and the current UTC year down through 2020", async () => {
    render(<VulnerabilitiesTable />);
    await screen.findByText("CVE-2026-12345");

    const yearSelect = screen.getByLabelText("Publication year");
    const options = within(yearSelect).getAllByRole("option");
    const currentYear = new Date().getUTCFullYear();

    expect(options.map((option) => option.textContent)).toEqual([
      "All years",
      ...Array.from(
        { length: currentYear - 2019 },
        (_value, index) => String(currentYear - index),
      ),
    ]);
    expect(options.map((option) => option.getAttribute("value"))).not.toContain(
      String(currentYear + 1),
    );
    expect(options.map((option) => option.getAttribute("value"))).not.toContain(
      "2019",
    );
  });

  test("does not apply typed search until Apply and submits trimmed combined filters", async () => {
    const user = userEvent.setup();
    const currentYear = new Date().getUTCFullYear();
    render(<VulnerabilitiesTable />);
    await screen.findByText("CVE-2026-12345");

    await user.type(screen.getByLabelText("Search CVEs"), "  CVE-2026  ");
    expect(fetchVulnerabilitiesMock).toHaveBeenCalledTimes(1);
    await user.selectOptions(
      screen.getByLabelText("Publication year"),
      String(currentYear),
    );
    expect(fetchVulnerabilitiesMock).toHaveBeenCalledTimes(1);
    await user.selectOptions(screen.getByLabelText("Severity"), "high");
    await user.selectOptions(screen.getByLabelText("Geographic scope"), "uae");
    await user.selectOptions(screen.getByLabelText("UAE relevance"), "confirmed");
    await user.selectOptions(screen.getByLabelText("Rows"), "25");
    await user.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        {
          geographic_scope: "uae",
          limit: 25,
          offset: 0,
          published_year: currentYear,
          q: "CVE-2026",
          severity: "high",
          uae_relevance_status: "confirmed",
        },
        expect.any(AbortSignal),
      ),
    );
  });

  test("Clear removes filters while preserving the selected row limit", async () => {
    const user = userEvent.setup();
    const currentYear = new Date().getUTCFullYear();
    render(<VulnerabilitiesTable />);
    await screen.findByText("CVE-2026-12345");

    await user.selectOptions(screen.getByLabelText("Severity"), "medium");
    await user.selectOptions(
      screen.getByLabelText("Publication year"),
      String(currentYear),
    );
    await user.selectOptions(screen.getByLabelText("Rows"), "25");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await user.click(screen.getByRole("button", { name: "Clear" }));

    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        {
          geographic_scope: undefined,
          limit: 25,
          offset: 0,
          published_year: undefined,
          q: "",
          severity: undefined,
          uae_relevance_status: undefined,
        },
        expect.any(AbortSignal),
      ),
    );
    expect(screen.getByLabelText("Publication year")).toHaveValue("");
  });

  test("distinguishes unfiltered and filtered empty states", async () => {
    const user = userEvent.setup();
    fetchVulnerabilitiesMock.mockResolvedValue({
      status: "success",
      data: makeVulnerabilityList({ items: [], total: 0 }),
    });
    render(<VulnerabilitiesTable />);

    expect(await screen.findByText("No vulnerabilities found")).toBeVisible();
    await user.selectOptions(screen.getByLabelText("Severity"), "low");
    expect(
      await screen.findByText("No vulnerabilities match the selected filters"),
    ).toBeVisible();
  });

  test("paginates by the row limit and prevents repeated navigation while loading", async () => {
    const user = userEvent.setup();
    const secondPage = deferred<VulnerabilityListResult>();
    fetchVulnerabilitiesMock
      .mockResolvedValueOnce({
        status: "success",
        data: makeVulnerabilityList({ total: 22 }),
      })
      .mockReturnValueOnce(secondPage.promise)
      .mockResolvedValueOnce({
        status: "success",
        data: makeVulnerabilityList({ total: 22 }),
      });

    render(<VulnerabilitiesTable />);
    expect(await screen.findByText("Showing 1-10 of 22 stored CVEs")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("Loading stored vulnerabilities")).toBeVisible();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ limit: 10, offset: 10 }),
      expect.any(AbortSignal),
    );

    secondPage.resolve({
      status: "success",
      data: makeVulnerabilityList({ total: 22, offset: 10 }),
    });
    expect(await screen.findByText("Showing 11-20 of 22 stored CVEs")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("Showing 1-10 of 22 stored CVEs")).toBeVisible();
  });

  test("changing the row limit resets pagination to zero", async () => {
    const user = userEvent.setup();
    fetchVulnerabilitiesMock.mockResolvedValue({
      status: "success",
      data: makeVulnerabilityList({ total: 60 }),
    });
    render(<VulnerabilitiesTable />);
    await screen.findByText("Showing 1-10 of 60 stored CVEs");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ offset: 10 }),
        expect.any(AbortSignal),
      ),
    );

    await user.selectOptions(screen.getByLabelText("Rows"), "25");
    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ limit: 25, offset: 0 }),
        expect.any(AbortSignal),
      ),
    );
  });

  test("Apply resets pagination and the applied year persists across pages", async () => {
    const user = userEvent.setup();
    const currentYear = new Date().getUTCFullYear();
    fetchVulnerabilitiesMock.mockResolvedValue({
      status: "success",
      data: makeVulnerabilityList({ total: 22 }),
    });
    render(<VulnerabilitiesTable />);
    await screen.findByText("Showing 1-10 of 22 stored CVEs");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ offset: 10 }),
        expect.any(AbortSignal),
      ),
    );

    const callCountBeforeSelection = fetchVulnerabilitiesMock.mock.calls.length;
    await user.selectOptions(
      screen.getByLabelText("Publication year"),
      String(currentYear),
    );
    expect(fetchVulnerabilitiesMock).toHaveBeenCalledTimes(callCountBeforeSelection);
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({
          offset: 0,
          published_year: currentYear,
        }),
        expect.any(AbortSignal),
      ),
    );

    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(fetchVulnerabilitiesMock).toHaveBeenLastCalledWith(
        expect.objectContaining({
          offset: 10,
          published_year: currentYear,
        }),
        expect.any(AbortSignal),
      ),
    );
  });

  test("detail links preserve applied list state in a safe return URL", async () => {
    const user = userEvent.setup();
    fetchVulnerabilitiesMock.mockResolvedValue({ status: "success", data: makeVulnerabilityList({ total: 52 }) });
    render(<VulnerabilitiesTable />);
    await screen.findByText("CVE-2026-12345");
    await user.type(screen.getByLabelText("Search CVEs"), "CVE-2026");
    await user.selectOptions(screen.getByLabelText("Severity"), "high");
    await user.selectOptions(screen.getByLabelText("Geographic scope"), "uae");
    await user.selectOptions(screen.getByLabelText("UAE relevance"), "confirmed");
    await user.selectOptions(screen.getByLabelText("Rows"), "25");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    const href = screen.getByRole("link", { name: "CVE-2026-12345" }).getAttribute("href") ?? "";
    expect(decodeURIComponent(href)).toContain("returnTo=/vulnerabilities?q=CVE-2026&severity=high&scope=uae&relevance=confirmed&limit=25&offset=25");
  });

  test("restores filters, row count, and pagination from the return URL", async () => {
    window.history.replaceState({}, "", "/vulnerabilities?q=CVE-2026&severity=high&scope=uae&limit=25&offset=25");
    render(<VulnerabilitiesTable />);
    await waitFor(() => expect(fetchVulnerabilitiesMock).toHaveBeenCalledWith(expect.objectContaining({ q: "CVE-2026", severity: "high", geographic_scope: "uae", limit: 25, offset: 25 }), expect.any(AbortSignal)));
    expect(screen.getByLabelText("Search CVEs")).toHaveValue("CVE-2026");
    expect(screen.getByLabelText("Rows")).toHaveValue("25");
    const detailLink = await screen.findByRole("link", { name: "CVE-2026-12345" });
    expect(decodeURIComponent(detailLink.getAttribute("href") ?? "")).toContain("returnTo=/vulnerabilities?q=CVE-2026&severity=high&scope=uae&limit=25&offset=25");
  });

  test("uses Overview as the return context when embedded on Overview", async () => {
    render(<VulnerabilitiesTable originPath="/" />);
    const link = await screen.findByRole("link", { name: "CVE-2026-12345" });
    expect(link).toHaveAttribute("href", "/vulnerabilities/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee?returnTo=%2F");
  });

  test.each([
    ["controlled error", async () => ({ status: "error" as const })],
    [
      "rejected promise",
      async () => {
        throw new Error("private vulnerability failure");
      },
    ],
  ])("renders a sanitized message for a %s", async (_label, implementation) => {
    fetchVulnerabilitiesMock.mockImplementation(implementation);
    render(<VulnerabilitiesTable />);

    expect(await screen.findByText("Vulnerabilities unavailable")).toBeVisible();
    expect(screen.queryByText("private vulnerability failure")).not.toBeInTheDocument();
  });

  test("aborts the old request when a filter changes and keeps the newer result", async () => {
    const user = userEvent.setup();
    let firstSignal: AbortSignal | undefined;
    fetchVulnerabilitiesMock
      .mockImplementationOnce((_filters, signal) => {
        firstSignal = signal;
        return pendingUntilAbort(signal);
      })
      .mockResolvedValueOnce({
        status: "success",
        data: makeVulnerabilityList({
          items: [makeVulnerability({ title: "Newest filtered CVE" })],
        }),
      });

    const { unmount } = render(<VulnerabilitiesTable />);
    await user.selectOptions(screen.getByLabelText("Severity"), "critical");

    expect(await screen.findByText("Newest filtered CVE")).toBeVisible();
    expect(firstSignal?.aborted).toBe(true);
    expect(screen.queryByText("Vulnerabilities unavailable")).not.toBeInTheDocument();
    unmount();
  });

  test("provides an accessible pagination label", async () => {
    render(<VulnerabilitiesTable />);
    await screen.findByText("CVE-2026-12345");

    const pagination = screen.getByLabelText("Vulnerability table pagination");
    expect(within(pagination).getByRole("button", { name: "Previous" })).toBeDisabled();
  });
});
