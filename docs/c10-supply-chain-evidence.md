# C10 supply-chain evidence

## Scope and method

Reviewed production manifests, lockfiles, all production Dockerfiles, Compose/Caddy configuration, environment templates, tracked Git content/history, runtime image configuration/history, and formal generated SBOMs. The ignored developer `.env` files were neither opened nor scanned. Raw scanner JSON stayed outside the repository.

## Dependency vulnerability audits

| Target | Tool | Final result | Disposition |
|---|---|---|---|
| Python production manifest | `pip-audit` 2.10.1, `backend/requirements.prod.txt` | No known vulnerabilities | PASS |
| Python installed environment consistency | pip 26.1.2 `pip check` | No broken requirements | PASS |
| Frontend production tree | npm 11.6.2 `npm audit --omit=dev` | 0 info/low/moderate/high/critical | PASS after C10-F-001 |
| Frontend complete development tree | npm audit | 3 High, 0 Critical; all indirect: `brace-expansion`, `js-yaml`, `undici` | FOLLOW-UP: development/test tooling only; production audit is clean |

Next.js was updated from 16.2.9 to 16.3.0, and the production `nanoid` resolution is constrained to 3.3.17. The Linux lockfile was synchronized and `npm ci` plus the production Docker build succeeded. Audit/SBOM tools were installed only in a system temporary tool environment or invoked with `npx`; no scanner was added to runtime manifests.

## Formal SBOMs

| Artifact | Generator | Format | Final validation |
|---|---|---|---|
| `security/sbom/backend.cdx.json` | `cyclonedx-py` 7.3.1 | CycloneDX JSON 1.6, 15 components | Generator validation passed; no local path/credential-like match |
| `security/sbom/frontend.cdx.json` | `@cyclonedx/cyclonedx-npm` 6.0.0 | CycloneDX JSON 1.6, 53 components / 55 dependency nodes | Generator validation passed; no local path/credential-like match |

Hashes and regeneration notes are in `security/sbom/README.md`.

## Direct production dependency licences and provenance

Python identifiers come from installed package metadata because the requirements-mode SBOM did not emit licence fields. `reportlab` and `stix2` publish non-SPDX/ambiguous BSD metadata; that is recorded as a metadata limitation, not a demonstrated legal blocker.

| Backend dependency | Version | Licence metadata | Source of truth |
|---|---:|---|---|
| alembic | 1.18.5 | MIT | requirements + installed metadata + SBOM |
| argon2-cffi | 25.1.0 | MIT | same |
| fastapi | 0.141.1 | MIT | same |
| feedparser | 6.0.12 | BSD-2-Clause | same |
| httpx | 0.28.1 | BSD-3-Clause | same |
| idna | 3.18 | BSD-3-Clause | same |
| prefect | 3.8.1 | Apache-2.0 | same |
| psycopg | 3.3.4 | LGPL-3.0-only | same |
| pydantic | 2.13.4 | MIT | same |
| pydantic-settings | 2.14.2 | MIT | same |
| python-dotenv | 1.2.2 | BSD-3-Clause | same |
| reportlab | 5.0.0 | vendor BSD text (non-SPDX metadata) | same |
| sqlalchemy | 2.0.51 | MIT | same |
| stix2 | 3.0.2 | `BSD` (ambiguous metadata) | same |
| uvicorn | 0.49.0 | BSD-3-Clause | same |

| Frontend direct dependency | Version | Licence | Source of truth |
|---|---:|---|---|
| next | 16.3.0 | MIT | package/lock + SBOM |
| react | 19.2.7 | MIT | package/lock + SBOM |
| react-dom | 19.2.7 | MIT | package/lock + SBOM |

## Container and image evidence

All Dockerfile `FROM` entries are digest-pinned. Runtime services use non-root users where supported, read-only filesystems, dropped capabilities, `no-new-privileges`, bounded resources/logs, private networks, and file/reference secret delivery. Caddy was upgraded from 2.10.2 to the official 2.11.4 Alpine digest for C10-F-007. Independent review then removed the non-reproducible broad `apk upgrade` (C10-F-010). A no-upgrade scan exposed five fixable Alpine findings; the final derivative mutates only exact versions `c-ares=1.34.8-r0`, `curl=8.20.0-r0`, and `libcurl=8.20.0-r0`.

| Exact deterministic mutation | Pinned base version | Final version | Demonstrated advisories removed |
|---|---:|---:|---|
| `c-ares` | 1.34.6-r0 | 1.34.8-r0 | CVE-2026-33630 |
| `curl` | 8.19.0-r0 | 8.20.0-r0 | CVE-2026-5773, CVE-2026-6276 |
| `libcurl` | 8.19.0-r0 | 8.20.0-r0 | CVE-2026-5773, CVE-2026-6276 |

The application dependency manifests did not change during hardening. Both CycloneDX files remained byte-identical at the hashes recorded in `security/sbom/README.md` and parsed successfully as CycloneDX 1.6 JSON.

Trivy 0.67.2 High/Critical results:

| Image | High | Critical | Interpretation / disposition |
|---|---:|---:|---|
| `alpha-data-backend:c10-validation` | 21 | 4 | 19 High/4 Critical are currently unfixed Debian base-package advisories. The two fixable Python hits (`msgpack`, `setuptools`) are layer-history false positives: both packages are absent from the final runtime metadata after a no-cache build. No reachable application path to the reported base utilities/Perl runtime was demonstrated. ACCEPTED LIMITATION. |
| `alpha-data-frontend:c10-validation` | 6 | 1 | All seven hits are build-layer packages (`undici`, `brace-expansion`, `tar`, `ip-address`) absent from the final standalone runtime filesystem; npm production audit is zero. Scanner layer-history limitation, not a shipped package finding. |
| `alpha-data-caddy:c10-hardening` | 5 | 0 | Final deterministic image ID `sha256:824e6c219539df5b88943352d8f046c78811e94fabb9d7fc88a873d794bac414`. Alpine result is 0 High/0 Critical after the three exact package pins; all five remaining findings are embedded in the official Caddy 2.11.4 Go binary. Admin is off, only h1/h2 are enabled, and no gRPC or `os.Root` route is configured. ACCEPTED LIMITATION pending an upstream Caddy rebuild. |
| `alpha-data-postgres:c09-validation` | 14 | 1 | Findings are in the image's Go startup helper; PostgreSQL is private-network only and no post-startup path was demonstrated. Retained C09 image was not deleted or presented as a rebuilt C10 artifact. FOLLOW-UP vendor refresh. |
| `alpha-data-prefect:3.8.1-python3.13` | 90 | 17 | Mostly base/build packages in the retained internal orchestration image; 15 have fixes. Prefect has no edge route and accepts only fixed project flows. Requires a separately tested upstream Prefect/base refresh rather than an unbounded C10 platform upgrade. FOLLOW-UP before public production. |
| `prom/prometheus:v3.7.3` | 72 | 4 | Retained pinned monitoring image, isolated on the internal monitoring network; no edge route or arbitrary scrape target. FOLLOW-UP vendor refresh before public production. |
| `prom/alertmanager:v0.28.1` | 62 | 2 | Retained pinned internal alerting image; no edge route and external delivery is not activated. FOLLOW-UP vendor refresh before public production. |
| `alpha-data-backup-tool:c09-docker-validation` | 0 | 0 | PASS; retained C09 resource unchanged. |

The nonzero support-image counts are explicit staging/release inputs, not hidden pass results. No third-party image was rebuilt from unreviewed source merely to suppress scanner output. The final Caddy image builds from the exact base digest, runs as `10001:10001`, retains capability removal, passes actual Caddyfile validation, and its project layer history contains only the three exact package versions and fixed identity/ownership operations. Image config/history inspection found no sensitive environment-name entry or literal secret candidate.

## Secret scanning and private-key marker classification

- Gitleaks 8.28.0 scanned all 117 Git commits with redaction and a path-aware tracked-only working snapshot. That snapshot returned zero findings. A final pathless stdin recheck of the current tracked and intended untracked text (about 6.94 MB) returned only the same two placeholder `NVD_API_KEY=` lines in the tracked example environment files; no value is present and both are false positives. The history scan likewise returned only those two placeholders.
- The two original private-key marker candidate files are `backend/tests/test_operational_persistence_postgresql.py` and `backend/tests/test_operational_persistence_service.py`. They contain four begin-marker canary strings and no end marker or key body. They are inert secret-redaction test fixtures, not private keys.
- No ignored runtime `.env`, authorization header, cookie, database URL, password, token, private key body, or scanner candidate value is included in C10 evidence.

## Residual supply-chain decisions

- ACCEPTED LIMITATION: upstream/base-image advisories without a demonstrated configured attack path remain visible above; C11/staging must rerun current scans before public activation.
- FOLLOW-UP: adopt a reviewed Python transitive constraints/lock workflow; current production direct requirements are exact but transitives resolve at build time.
- FOLLOW-UP: normalize/confirm SPDX licence metadata for `reportlab` and `stix2` during legal/procurement review.
- FOLLOW-UP: refresh Prefect, Prometheus, Alertmanager, and PostgreSQL helper images with their owning regression scopes before public production.
- FOLLOW-UP: resolve the whole-tree ESLint 10-error baseline in unchanged components for the newly enforced `react-hooks/set-state-in-effect` rule. All C10-changed frontend source and test files pass ESLint.

Reviewer/sign-off: **Pending independent review**.
