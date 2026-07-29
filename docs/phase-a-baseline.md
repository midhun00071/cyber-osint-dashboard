# Phase A Baseline for Phase B

## Purpose and authority

This register records the auditable Phase A baseline accepted for the start of
Phase B under task B0-01. Binary evidence remains outside Git. The corrected
Phase B workbook is the authoritative active plan, with B0-01 as its first task;
the Phase A workbook is retained as historical evidence only.

## Repository checkpoint

| Item | Verified value |
| --- | --- |
| Branch | `dev` |
| Clean checkpoint | `c15de994a8c783685fb167f57c21f397584487c1` |
| HEAD and `origin/dev` | Matched at the verified checkpoint |
| Latest commit | `c15de99 updated agents.md` |
| P9-10 implementation commit | `10f066e P9-10 Add fixed-policy TAXII client` |

## External evidence inventory

These binary artifacts are retained outside Git. Their hashes are recorded for
identity and integrity checks; this register does not embed or reproduce them.

| Artifact | SHA-256 |
| --- | --- |
| `Alpha_Data_Project_Task_Sheet_Updated_Through_2026-07-28.xlsx` | `A709DFA4FC7E1DD34AFFA3C47399E2879A4BC616965ED722AE4C2EF868C58719` |
| `Alpha_Data_Phase_B_Production_Task_Sheet_Corrected_2026-07-28.xlsx` | `7CE16918F672D802A2FCC226E1EE6AA9CAA4D532AADD4494143485038A4BDFFE` |
| `Alpha_Data_Daily_Progress_Report_2026-07-28.pdf` | `19FB32B7C2E9D4514ABCCC145BB718D402831244B40B7B4233FBD50D4B612540` |
| `cyber-osint-dashboard-c15de99-20260729-195730.zip` | `1ACF2F494DF19EBFD558742B914A371B37DADCE76B09A85F3FE4A2D30ACFA693` |
| `p9-10-taxii-client-final-review-20260729-200959.zip` | `7B0028CFB3AADA97EAFF0AFD7336994533D2376A935EFBF5D55F386AC4623EF7` |

The 29 July P9-10 ZIP is a reconstructed focused evidence archive, not the
original 28 July independent-review archive. It contains 12 focused files that
match the corresponding tracked repository files after CRLF/LF normalisation.
No known secrets, environment files, Git metadata, databases, caches, or build
output are present.

The original archive was reported as
`p9-10-taxii-client-final-review-20260728-112406.zip`, with reported SHA-256
`34EB7ADC835767B2E7DE272FC50ED06F4092976A457A9CB9F3D4C9CA6635E8AD`.
It is unavailable and was not inspected or recovered.

## Phase A status and reusable foundations

The Phase A workbook contains 73 official task rows: 63 Completed, 2 In
Progress, and 8 Not Started. P9-10 is Completed. The following completed work is
reused as foundation in Phase B:

- P9-08: normalized defensive indicator identity and provenance foundation.
- P9-09: deterministic offline IOC extraction and publication relationships.
- P9-10: bounded STIX 2.1 validation and persistence plus the fixed-policy TAXII
  2.1 client.

This reuse does not transfer Phase A task rows into the active plan. Completed
or incomplete Phase A tasks must not be copied into the Phase B Task Plan or
receive duplicate completion credit. Unfinished P9 work is governed by the
corrected Phase B reassignment plan.

## Known limitation

The migration-history assertion reads committed migration files as raw bytes
before calculating SHA-256. On Windows checkouts that convert LF line endings
to CRLF, the raw-byte digest can differ even when the migration's normalized
text and logical content are unchanged. This line-ending-sensitive assertion
must not be treated by itself as evidence that migration history changed. B0-01
does not edit migration history, migration tests, or their expected hashes, and
no executable test is required for this documentation-only change.
