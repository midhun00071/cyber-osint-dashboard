import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";

import { AccessDenied } from "@/components/auth/AccessDenied";

describe("AccessDenied", () => {
  test("keeps authorization denial distinct from authentication expiry", () => {
    render(<AccessDenied />);
    expect(screen.getByRole("heading", { name: "Access denied" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Return to overview" })).toHaveAttribute("href", "/");
  });
});
