import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { AuthProvider, getSafeReturnPath, useAuth } from "@/components/auth/AuthProvider";
import { fetchPrincipal, login as requestLogin } from "@/services/authApi";
import type { Principal } from "@/types/auth";

let pathname = "/operations";
vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ replace: vi.fn() }),
}));
vi.mock("@/services/authApi", () => ({ fetchPrincipal: vi.fn(), login: vi.fn(), logout: vi.fn() }));
const fetchPrincipalMock = vi.mocked(fetchPrincipal);
const requestLoginMock = vi.mocked(requestLogin);

function Probe() {
  const auth = useAuth();
  return <>
    <div>{auth.state}:{auth.principal?.display_name ?? "none"}</div>
    <button type="button" onClick={() => void auth.bootstrap()}>bootstrap</button>
    <button type="button" onClick={() => void auth.login("operator", "secret")}>login</button>
  </>;
}

describe("AuthProvider", () => {
  beforeEach(() => {
    pathname = "/operations";
    fetchPrincipalMock.mockResolvedValue({ status: "anonymous" });
    requestLoginMock.mockResolvedValue({ status: "invalid" });
  });
  test("performs one bootstrap and publishes an authenticated principal", async () => {
    fetchPrincipalMock.mockResolvedValue({ status: "authenticated", principal: { public_id: "user", display_name: "Operator", role: "ingestion_operator", permissions: ["ingestion.read"], account_expires_at: null } });
    render(<AuthProvider><Probe /></AuthProvider>);
    expect(screen.getByText("bootstrapping:none")).toBeVisible();
    await waitFor(() => expect(screen.getByText("authenticated:Operator")).toBeVisible());
    expect(fetchPrincipalMock).toHaveBeenCalledTimes(1);
  });

  test("keeps the principal and clears access denied after navigation", async () => {
    fetchPrincipalMock.mockResolvedValue({ status: "authenticated", principal: { public_id: "user", display_name: "Operator", role: "ingestion_operator", permissions: ["ingestion.read"], account_expires_at: null } });
    const rendered = render(<AuthProvider><Probe /></AuthProvider>);
    await waitFor(() => expect(screen.getByText("authenticated:Operator")).toBeVisible());
    window.dispatchEvent(new Event("alpha-data:access-denied"));
    expect(await screen.findByText("access_denied:Operator")).toBeVisible();
    pathname = "/";
    rendered.rerender(<AuthProvider><Probe /></AuthProvider>);
    await waitFor(() => expect(screen.getByText("authenticated:Operator")).toBeVisible());
  });

  test("uses only validated local return destinations", () => {
    const uuid = "11111111-1111-4111-8111-111111111111";
    expect(getSafeReturnPath("/sources")).toBe("/sources");
    expect(getSafeReturnPath(`/articles/${uuid}`)).toBe(`/articles/${uuid}`);
    expect(getSafeReturnPath("https://attacker.invalid")).toBe("/");
    expect(getSafeReturnPath("//attacker.invalid")).toBe("/");
    expect(getSafeReturnPath("%2F%2Fattacker.invalid")).toBe("/");
    expect(getSafeReturnPath("%E0%A4%A")).toBe("/");
    expect(getSafeReturnPath("/unknown")).toBe("/");
  });

  test("quietly aborts an older bootstrap without overwriting a later valid session", async () => {
    const unhandled = vi.fn();
    window.addEventListener("unhandledrejection", unhandled);
    let resolveBootstrap: ((value: { status: "authenticated"; principal: Principal }) => void) | undefined;
    fetchPrincipalMock.mockImplementationOnce((signal) => new Promise((resolve) => {
      resolveBootstrap = resolve;
      signal?.addEventListener("abort", () => undefined, { once: true });
    }));
    requestLoginMock.mockResolvedValueOnce({ status: "authenticated", principal: { public_id: "user", display_name: "Operator", role: "ingestion_operator", permissions: ["ingestion.read"], account_expires_at: null } });
    render(<AuthProvider><Probe /></AuthProvider>);
    const bootstrapSignal = fetchPrincipalMock.mock.calls[0][0];
    fireEvent.click(screen.getByRole("button", { name: "login" }));
    await waitFor(() => expect(screen.getByText("authenticated:Operator")).toBeVisible());
    expect(bootstrapSignal?.aborted).toBe(true);
    resolveBootstrap?.({ status: "authenticated", principal: { public_id: "user", display_name: "Operator", role: "ingestion_operator", permissions: ["ingestion.read"], account_expires_at: null } });
    await waitFor(() => expect(screen.getByText("authenticated:Operator")).toBeVisible());
    expect(screen.queryByText(/recoverable_error/)).not.toBeInTheDocument();
    expect(unhandled).not.toHaveBeenCalled();
    window.removeEventListener("unhandledrejection", unhandled);
  });
});
