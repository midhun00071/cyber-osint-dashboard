# C10 OWASP, ASVS, and SSDF gap-assessment matrix

This is a traceable project gap assessment, not an OWASP/ASVS certification or blanket compliance claim. ASVS identifiers and descriptions were selected from the official OWASP ASVS 5.0.0 CSV; 30 selected requirements are applicable and pass after the frozen remediations, two are not applicable, and none remain failed. Reviewer fields remain open for independent review.

Status vocabulary: **PASS**, **FAIL**, **NOT APPLICABLE**. Finding references are in `docs/c10-security-audit.md`.

## OWASP Top 10:2025

| Control | Area | Applicability and project evidence | Status | Findings / residual risk | Reviewer |
|---|---|---|---|---|---|
| A01 | Broken Access Control | Backend permission dependencies, public UUID lookup, CSRF, strict host/CORS; `test_c10_api_security.py`, authorization/auth suites | PASS | Process-local rate limiting is accepted | Pending |
| A02 | Security Misconfiguration | Production configuration rejects wildcard hosts/CORS, debug/insecure cookies/default secrets; Caddy headers and exact routes; Compose tests | PASS | Backend docs are private-network only | Pending |
| A03 | Software Supply Chain Failures | Pinned manifests/base images, exact package mutations, final production audits, CycloneDX SBOMs, Trivy and Gitleaks evidence | PASS | C10-F-001/F-006/F-007/F-010 resolved; three High dev-only advisories accepted for follow-up | Pending |
| A04 | Cryptographic Failures | TLS terminates at approved edge; secure cookies; modern password hashing; secrets via environment/file references; no home-grown cryptography | PASS | Public TLS proof is a staging/manual gate | Pending |
| A05 | Injection | ORM/SQLAlchemy expressions, argv subprocesses, React text escaping, fixed headers, CSV neutralization, plain PDF; C10 injection/browser tests | PASS | No demonstrated injection path | Pending |
| A06 | Insecure Design | Immutable roles/source policies, approval gates, idempotency, lifecycle invariants, explicit accepted limitations | PASS | MFA and distributed limiting are later architecture decisions | Pending |
| A07 | Authentication Failures | Session expiry/version/revocation, login throttling, password policy, CSRF/Origin checks, `no-store`; C06 and C10 API tests | PASS | Single-factor local authentication accepted for this release stage | Pending |
| A08 | Software or Data Integrity Failures | Strict schemas, provenance, transaction/rollback, checkpoint-after-commit, deterministic idempotency; C10 logic tests | PASS | No production fallback/mock path demonstrated | Pending |
| A09 | Security Logging and Alerting Failures | Structured redacted logs, immutable audit events, safe details, synthetic canary tests | PASS | External alert delivery remains a manual/later item | Pending |
| A10 | Mishandling of Exceptional Conditions | Sanitized exception handlers, fail-closed audit/transaction paths, bounded outbound error states; logging/error and logic tests | PASS | No fail-open success path demonstrated | Pending |

## OWASP API Security Top 10:2023

| Control | Area | Applicability and project evidence | Status | Findings / residual risk | Reviewer |
|---|---|---|---|---|---|
| API1 | Broken Object Level Authorization | Typed public IDs plus backend permission dependencies; admin, content, analyst, operations BOLA tests | PASS | None demonstrated | Pending |
| API2 | Broken Authentication | Cookie session contract, secure expiry/refresh/revoke, login limiter and CSRF; C06 auth suites | PASS | Single factor accepted | Pending |
| API3 | Broken Object Property Level Authorization | Allow-listed response models and strict mutation schemas; mass-assignment tests | PASS | None demonstrated | Pending |
| API4 | Unrestricted Resource Consumption | Query/page/search/row/byte/depth/time bounds plus 1,000,000-byte and 1,024-message request ceilings | PASS | C10-F-005/F-009 resolved; limiter is process-local | Pending |
| API5 | Broken Function Level Authorization | Permission matrix enforced at every protected backend route; cross-role 403 tests | PASS | None demonstrated | Pending |
| API6 | Unrestricted Access to Sensitive Business Flows | Login throttling, ingestion permissions, idempotency, state and source approval gates | PASS | Horizontal/distributed enforcement is later work | Pending |
| API7 | Server Side Request Forgery | Immutable HTTPS destinations, fixed-feed redirect rejection, pagination revalidation, `trust_env=False`; outbound matrix/tests | PASS | C10-F-003/F-008 resolved | Pending |
| API8 | Security Misconfiguration | Exact hosts/CORS, security headers, safe cookies/errors, private metrics/docs | PASS | CSP inline allowance documented below | Pending |
| API9 | Improper Inventory Management | 42 generated paths/43 operations plus private metrics and docs inventory | PASS | Internal docs must stay edge-inaccessible | Pending |
| API10 | Unsafe Consumption of APIs | Time/byte/object/depth/media-type bounds, redirect rejection, hostile response tests, sanitized failures | PASS | C10-F-004/F-008 resolved | Pending |

## Applicable OWASP ASVS 5.0.0 requirements

| ASVS ID | Area | Project evidence | Status | Finding / residual risk | Reviewer |
|---|---|---|---|---|---|
| v5.0.0-1.2.1 | Contextual HTTP/HTML/XML output encoding | React text output, Pydantic JSON, fixed response headers; browser/injection tests | PASS | None | Pending |
| v5.0.0-1.2.2 | Safe dynamic URLs/protocols | `safeExternalUrl.ts`, `apiClient.ts`, SafeExternalLink and C10 frontend tests | PASS | C10-F-002 resolved | Pending |
| v5.0.0-1.2.4 | Parameterized database queries | SQLAlchemy ORM/expression construction; C10 inert SQL-string tests | PASS | None | Pending |
| v5.0.0-1.2.5 | OS command injection prevention | Fixed executables and argv arrays in production scripts; validation and mocked tests | PASS | None | Pending |
| v5.0.0-1.2.10 | Spreadsheet formula injection prevention | Report CSV cell neutralization including control/whitespace prefixes; report tests | PASS | None | Pending |
| v5.0.0-1.3.2 | Avoid dynamic code evaluation | Required static sink search; no production `eval`/`exec`/Function construction | PASS | None | Pending |
| v5.0.0-1.3.6 | SSRF prevention | Fixed source policy, fixed-feed redirect rejection, URL revalidation where explicitly allowed, no proxy inheritance | PASS | C10-F-003/F-008 resolved | Pending |
| v5.0.0-1.5.1 | Safe XML parsing | defused/bounded XML parsing; official RSS/adaptor tests | PASS | None | Pending |
| v5.0.0-1.5.2 | Safe deserialization | JSON/XML/HTML structure, depth, count and byte limits; no unsafe pickle/yaml loader | PASS | None | Pending |
| v5.0.0-2.1.1 | Documented input validation | Pydantic/query schemas and complete API inventory | PASS | None | Pending |
| v5.0.0-2.1.3 | Documented business limits | API/outbound matrices, report/source limits and lifecycle rules | PASS | None | Pending |
| v5.0.0-2.2.1 | Input validation | Typed schemas, exact query allow-lists, canonical UUID/slug/enum validation | PASS | None | Pending |
| v5.0.0-2.2.2 | Trusted-server validation | All security decisions are backend-side; frontend hiding is not authorization | PASS | None | Pending |
| v5.0.0-2.3.2 | Business limit enforcement | Page/search/report/request/outbound quotas and byte/message request ceilings enforced in services/clients | PASS | C10-F-005/F-009 resolved | Pending |
| v5.0.0-2.3.3 | Transaction integrity | Explicit commit/rollback and audit-failure behavior; C10 logic tests | PASS | None | Pending |
| v5.0.0-2.4.1 | Anti-automation controls | Login and analyst read limiting plus idempotent ingestion operations | PASS | Process-local limiter accepted | Pending |
| v5.0.0-3.2.2 | Safe untrusted text rendering | React escaped rendering; no untrusted HTML sink; C10 browser tests | PASS | None | Pending |
| v5.0.0-3.3.1 | Cookie scope/attributes | Host-only secure cookie naming and bounded paths; auth tests | PASS | None | Pending |
| v5.0.0-3.3.2 | Secure cookies | Production requires Secure cookies | PASS | TLS evidence at staging gate | Pending |
| v5.0.0-3.3.3 | HttpOnly cookies | Session cookie is HTTP-only; auth tests | PASS | None | Pending |
| v5.0.0-3.3.4 | SameSite cookies | Explicit SameSite policy plus Origin/CSRF checks | PASS | None | Pending |
| v5.0.0-3.4.1 | HSTS | Caddy production header policy | PASS | Requires public TLS validation | Pending |
| v5.0.0-3.4.2 | CORS | Explicit HTTPS origin allow-list; credentials only for approved origin | PASS | None | Pending |
| v5.0.0-3.4.3 | Content Security Policy | Caddy CSP blocks objects/frames/base drift and limits sources | PASS | `'unsafe-inline'` remains required by verified Next build; defense-in-depth reduction accepted | Pending |
| v5.0.0-3.4.4 | MIME sniffing prevention | `X-Content-Type-Options: nosniff`; export headers/tests | PASS | None | Pending |
| v5.0.0-3.4.5 | Referrer policy | Caddy `Referrer-Policy` and safe external link policy | PASS | None | Pending |
| v5.0.0-3.4.6 | Clickjacking prevention | CSP `frame-ancestors 'none'` / frame header | PASS | None | Pending |
| v5.0.0-3.5.1 | CSRF prevention | Synchronizer token/header plus Origin and SameSite enforcement | PASS | None | Pending |
| v5.0.0-3.5.3 | HTTP method enforcement | Explicit route methods; method/content-type negative tests | PASS | None | Pending |
| v5.0.0-4.2.5 | Bounded outbound URIs/headers | Exact fixed-feed endpoints, redirect rejection, bounded API queries/keys, timeout and quota controls | PASS | C10-F-008 resolved | Pending |
| v5.0.0-4.3.1 | GraphQL query resource controls | Application exposes no GraphQL endpoint or parser | NOT APPLICABLE | Technology absent | Pending |
| v5.0.0-4.4.1 | WebSocket TLS | Application exposes no WebSocket endpoint | NOT APPLICABLE | Technology absent | Pending |

## Project SEC-01 through SEC-20

| Controls | Final status and evidence |
|---|---|
| SEC-01, SEC-02, SEC-05, SEC-06, SEC-08, SEC-09 | PASS: API inventory, role/CSRF/session/input/byte-and-message body-limit evidence; C10-F-009 resolved |
| SEC-03, SEC-04, SEC-16 | PASS: injection, React/URL, CSV/PDF/header review and C10 tests |
| SEC-07, SEC-13 | PASS: complete outbound policy review; C10-F-003/F-004/F-008 resolved |
| SEC-10, SEC-11 | PASS: secrets/config, audits, SBOM and deterministic image evidence; C10-F-001/F-006/F-007/F-010 resolved |
| SEC-12 | PASS: structured redaction, audit events, log canary tests; external delivery remains later |
| SEC-14, SEC-15 | PASS: transaction/checkpoint/idempotency/fake-success and test-integrity review |
| SEC-17 | PASS: complete generated and non-OpenAPI route inventory |
| SEC-18 | PASS/preserved: C09 backup/recovery controls unchanged; off-host destination is manual/later |
| SEC-19 | PASS/preserved: UAE automated access remains approval-gated |
| SEC-20 | PASS/preserved: completed official public-source governance was not reopened |

## NIST SSDF SP 800-218 v1.1 evidence mapping

| Practice | Bounded C10 evidence |
|---|---|
| PO.1 / PO.3 | Frozen acceptance, security requirements, roles, source policies, finding severity and review gates |
| PS.1 / PS.2 / PS.3 | Pinned manifests/images, generated CycloneDX SBOMs, provenance/license summary, secret scanning |
| PW.4 / PW.5 | Static sink review, complete security-critical source review, strict inputs and safe dependencies |
| PW.7 / PW.8 | Focused negative-path tests, full regression, scanner evidence and production image validation |
| RV.1 / RV.2 / RV.3 | Evidence-backed finding freeze, bounded remediation, regression/self-review, recorded follow-ups |

Reviewer/sign-off: **Pending independent review**.
