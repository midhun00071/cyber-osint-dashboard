import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";

import { SafeExternalLink } from "@/components/SafeExternalLink";

describe("SafeExternalLink", () => {
  test.each([
    ["HTTP", "http://example.test/report"],
    ["HTTPS", "https://example.test/report"],
  ])("renders a protected external anchor for a valid %s URL", (_label, url) => {
    render(<SafeExternalLink url={url}>Open report</SafeExternalLink>);

    expect(screen.getByRole("link", { name: "Open report" })).toHaveAttribute(
      "href",
      url,
    );
    expect(screen.getByRole("link", { name: "Open report" })).toHaveAttribute(
      "target",
      "_blank",
    );
    expect(screen.getByRole("link", { name: "Open report" })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
  });

  test.each([
    ["javascript scheme", "javascript:alert(1)"],
    ["data scheme", "data:text/html,unsafe"],
    ["credentials", "https://user:password@example.test/report"],
    ["protocol-relative URL", "//example.test/report"],
  ])("renders %s as non-clickable text", (_label, url) => {
    render(<SafeExternalLink url={url}>Open report</SafeExternalLink>);

    expect(screen.queryByRole("link", { name: "Open report" })).not.toBeInTheDocument();
    expect(screen.getByText("Open report")).toHaveAttribute("aria-disabled", "true");
  });

  test("renders markup-like child content as text", () => {
    render(
      <SafeExternalLink url="https://example.test/report">
        {"<img src=x onerror=alert(1)>"}
      </SafeExternalLink>,
    );

    expect(screen.getByRole("link")).toHaveTextContent(
      "<img src=x onerror=alert(1)>",
    );
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});
