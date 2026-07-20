import { strict as assert } from "node:assert";
import { createElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { SafeExternalLink } from "../src/components/SafeExternalLink";
import { getSafeExternalUrl } from "../src/utils/safeExternalUrl";

type ValidationLinkProps = Omit<
  Parameters<typeof SafeExternalLink>[0],
  "children"
> & { children?: ReactNode };

const ValidationSafeExternalLink = SafeExternalLink as (
  props: ValidationLinkProps,
) => ReturnType<typeof SafeExternalLink>;

const acceptedCases = new Map<string, string>([
  ["https://example.com/report", "https://example.com/report"],
  ["http://example.com/report", "http://example.com/report"],
  [
    "http://127.0.0.1:8000/lab-reference",
    "http://127.0.0.1:8000/lab-reference",
  ],
  [
    "https://example.com:8443/advisory?id=123#section",
    "https://example.com:8443/advisory?id=123#section",
  ],
  ["https://例え.テスト/report", "https://xn--r8jz45g.xn--zckzah/report"],
  ["  https://example.com/report  ", "https://example.com/report"],
]);

for (const [candidate, expected] of acceptedCases) {
  assert.equal(getSafeExternalUrl(candidate), expected);
}

const rejectedCases: readonly unknown[] = [
  null,
  undefined,
  123,
  "",
  "   ",
  "/relative",
  "//example.com",
  "javascript:alert(1)",
  "JaVaScRiPt:alert(1)",
  " data:text/html,test",
  "vbscript:msgbox(1)",
  "file:///tmp/file",
  "blob:https://example.com/id",
  "https://user:pass@example.com",
  "https://@example.com",
  "https://example.com:bad",
  "https://example.com:0",
  "https://example.com:",
  "https://[::1",
  "https://exam\tple.com",
  "https://example.com\n.evil.test",
  "https://example.com\r.evil.test",
  "https://example.com/has internal space",
  "https://example.com/\0value",
  "https://example.com/\u0085value",
  "https://example.com/\u200Bvalue",
  "https://",
];

for (const candidate of rejectedCases) {
  assert.doesNotThrow(() => getSafeExternalUrl(candidate));
  assert.equal(getSafeExternalUrl(candidate), null);
}

const validLinkMarkup = renderToStaticMarkup(
  createElement(
    ValidationSafeExternalLink,
    {
      className: "safeSourceLink",
      url: "https://example.com/report",
    },
    "Open source",
  ),
);

assert.match(validLinkMarkup, /^<a /);
assert.match(validLinkMarkup, /href="https:\/\/example\.com\/report"/);
assert.match(validLinkMarkup, /target="_blank"/);
assert.match(validLinkMarkup, /rel="noopener noreferrer"/);
assert.match(validLinkMarkup, />Open source<\/a>$/);

const fixturePayloads = [
  "<script>window.__xss_test = true</script>",
  '<img src=x onerror="window.__xss_test = true">',
  '<svg onload="window.__xss_test = true">',
] as const;

(globalThis as typeof globalThis & { __xss_test?: boolean }).__xss_test = false;

for (const payload of fixturePayloads) {
  const textMarkup = renderToStaticMarkup(createElement("p", null, payload));
  const unsafeLinkMarkup = renderToStaticMarkup(
    createElement(
      ValidationSafeExternalLink,
      {
        url: "javascript:alert(1)",
      },
      payload,
    ),
  );

  for (const markup of [textMarkup, unsafeLinkMarkup]) {
    assert.doesNotMatch(markup, /<(script|img|svg|iframe|a)(?:\s|>)/i);
    assert.match(markup, /&lt;/);
  }

  assert.match(unsafeLinkMarkup, /^<span /);
  assert.doesNotMatch(unsafeLinkMarkup, /href=/i);
}

assert.equal(
  (globalThis as typeof globalThis & { __xss_test?: boolean }).__xss_test,
  false,
);

const unicodeMarkup = renderToStaticMarkup(
  createElement("p", null, "Legitimate defensive intelligence — مرحباً بالعالم"),
);
assert.match(unicodeMarkup, /Legitimate defensive intelligence/);
assert.match(unicodeMarkup, /مرحباً بالعالم/);

console.log(
  `Safe rendering validation passed (${acceptedCases.size} accepted URLs, ${rejectedCases.length} rejected values, ${fixturePayloads.length} text payloads).`,
);
