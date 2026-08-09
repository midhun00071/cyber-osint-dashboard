# C10 CycloneDX SBOM artifacts

These machine-generated artifacts describe the direct production dependency manifests at the C10 checkpoint. They are evidence, not a vulnerability or license certification.

| Artifact | Generator | Input | CycloneDX | Components / dependency nodes | SHA-256 |
|---|---|---|---|---|---|
| `backend.cdx.json` | `cyclonedx-bom` / `cyclonedx-py` 7.3.1 | `backend/requirements.prod.txt` | 1.6 | 15 / 15 | `c984cbc99f0a1d26131a9d05e03dbccc759a6f552e07615c0f52409a465c9712` |
| `frontend.cdx.json` | `@cyclonedx/cyclonedx-npm` 6.0.0 | `frontend/package.json` and `package-lock.json`, production only | 1.6 | 53 / 55 | `75f99b5cec2d225e466b04c9275ae9f8deb785c4b2f5d3816281afaa6133da98` |

Both generators completed schema validation. The frontend generator used reproducible output and package-lock-only traversal. The repository's npm-native `npm sbom` path could not traverse the cross-platform optional dependency tree, so the recognized CycloneDX npm generator was used instead.

The artifacts were checked for local developer paths and credential-like fields; none matched. They must be regenerated after any production manifest or lockfile change. Raw scanner reports remain outside the repository; the bounded results are recorded in `docs/c10-supply-chain-evidence.md`.

Reviewer/sign-off: **Pending independent review**.
