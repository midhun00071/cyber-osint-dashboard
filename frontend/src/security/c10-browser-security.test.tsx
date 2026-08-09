import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";

import { SafeExternalLink } from "../components/SafeExternalLink";
import { getSafeExternalUrl } from "../utils/safeExternalUrl";

describe("C10 browser and external URL security", () => {
  test("renders hostile intelligence strings only as text", () => {
    const values = [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      '"</style><svg onload=alert(1)>',
      "&lt;script&gt;alert(1)&lt;/script&gt;",
      "Unicode text \u2014 safely displayed",
    ];

    render(<div>{values.map((value) => <p key={value}>{value}</p>)}</div>);

    for (const value of values) {
      expect(screen.getByText(value)).toBeVisible();
    }
    expect(document.querySelector("script, img, svg, style")).toBeNull();
  });

  test.each([
    "http://example.test/path",
    "javascript:alert(1)",
    "data:text/html,unsafe",
    "vbscript:msgbox(1)",
    "file:///tmp/example",
    "ftp://example.test/file",
    "//example.test/path",
    "https://user:password@example.test/",
    "https://example.test:8443/",
    "https://example.test\\attacker.test/",
    "https://example.test/%0aheader",
    "https://example.test/%7Fcontrol",
    "https://example.test/%zz",
    "https://example.test/%",
    " https://example.test/",
    "https://example.test/ ",
    "https://ex\u00e4mple.test/",
    "https://example%2etest/",
  ])("rejects ambiguous or unsafe external URL %s", (value) => {
    expect(getSafeExternalUrl(value)).toBeNull();
  });

  test("accepts canonical HTTPS links and normalizes mixed-case schemes", () => {
    expect(getSafeExternalUrl("HTTPS://Example.Test/path?q=1#section")).toBe(
      "https://example.test/path?q=1#section",
    );
    expect(getSafeExternalUrl("https://example.test:443/path")).toBe(
      "https://example.test/path",
    );
  });

  test("unsafe source URLs never become anchors", () => {
    render(<SafeExternalLink url="http://example.test">External source</SafeExternalLink>);
    expect(screen.queryByRole("link", { name: "External source" })).toBeNull();
    expect(screen.getByText("External source")).toHaveAttribute("aria-disabled", "true");
  });
});
