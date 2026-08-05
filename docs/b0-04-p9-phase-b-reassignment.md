# B0-04 P9-to-Phase-B Reassignment

> **C05 supersession (5 August 2026):** The P9-12/P9-13 commercial mappings,
> former B6-02 through B6-08 paid-source tasks, and APR-01 through APR-04 vendor
> gates below are retired historical traceability only. They are not unfinished,
> approval-gated, credential-gated, or planned work. Public Censys ARC/Rapid
> Response publication metadata remains distinct. C05 now means B6-01 paid-source
> retirement, B6-02 MITRE Enterprise ATT&CK, and B6-03 CERT-FR/UK NCSC RSS.

## 1. Document control

| Field | Value |
| --- | --- |
| Task | B0-04 — Reassign unfinished P9 work into Phase B |
| Artifact status | Reconciliation artifacts ready for independent review; not approved or complete |
| Reconciliation date | 30 July 2026 |
| Branch | `dev` |
| Source checkpoint | `6bafc45c53aab4ef385a54eab47b195a3d2b08b7` |
| Source commit | `6bafc45 B0-03 Freeze production MVP scope` |
| Dependency | B0-03 completed, independently reviewed, committed, and pushed |
| Active implementation plan | Official Phase B workbook `Task Plan` |
| Authoritative legacy crosswalk | This document and `docs/b0-04-p9-phase-b-mapping.csv` |
| Release deadline | 11 August 2026 |

This document reconciles legacy planning language only. It does not implement
P9 or Phase B work, update a task status or duration, record an approval, or
prove any replacement task complete.

## 2. Task, dependency and checkpoint

The mandatory checkpoint gate passed before repository inspection or drafting:

- branch was exactly `dev`;
- the working tree was clean;
- `git fetch origin` succeeded;
- local `HEAD` and refreshed `origin/dev` both equalled
  `6bafc45c53aab4ef385a54eab47b195a3d2b08b7`;
- `HEAD` was `B0-03 Freeze production MVP scope`; and
- B0-03 was the completed dependency.

No pull, branch switch, stage, commit, push, reset, restore, clean, deletion, or
history rewrite is authorized or performed by B0-04.

## 3. Executive reconciliation decision

P9-11 through P9-15 are unfinished legacy work. Their descriptions are retired
as active task instructions and mapped into the official Phase B Task Plan.
They remain visible for traceability but must not be separately scheduled,
estimated, implemented, completed, or reported.

The Phase B Task Plan is the active implementation plan. This B0-04 mapping is
the authoritative legacy-to-active crosswalk. Creating the crosswalk gives no
completion credit to a legacy task or replacement task and adds no planned
hours. Each replacement task retains its own acceptance, review, test, Git, and
evidence requirements.

## 4. Evidence sources and method

The reconciliation used these complete sources:

- `AGENTS.md`;
- `docs/b0-02-repository-ui-audit.md` and its complete 442-row inventory CSV;
- `docs/b0-03-production-mvp-scope.md` and its complete 121-row checklist CSV;
- `docs/phase-a-baseline.md`;
- `README.md`;
- the official workbook
  `Alpha_Data_Phase_B_Production_Task_Sheet_Updated_Through_2026-07-29.xlsx`;
- workbook ranges `P9 Reassignment!A1:F6`, `Task Plan!A1:V75`, and the
  `Approval Register`; and
- all 309 tracked repository paths returned by `git ls-files`.

The tracked repository was searched with one case-insensitive combined
`git grep` for P9-11 through P9-15 plus `threat entities`, `Censys enrichment`,
`commercial access`, `commercial API assessment`, `frontend views`,
`source-expansion review`, and `independent review`. The complete search
returned 35 tracked hits across 14 files: nine exact legacy-ID hits and 26
descriptive or contextual hits. Every result was read in context and classified
individually in section 16, including unrelated matches rather than omitting
them. The two untracked B0-04 artifacts were excluded from this pre-change
inventory by `git grep`.

The workbook mapping was compared to the replacement task titles,
descriptions, dependencies, approval states, and completion rules. A repository
reference was not treated as authoritative merely because it was already
tracked or matched a broad contextual term.

## 5. Historical Phase A completion boundary

P9-08 through P9-10 remain completed historical foundations and are not
reassigned:

- P9-08 — normalized defensive indicator identity and provenance;
- P9-09 — deterministic offline IOC extraction and publication relationships;
  and
- P9-10 — bounded STIX 2.1 validation and persistence plus the fixed-policy
  TAXII 2.1 client.

Phase B may depend on and extend those foundations. Their task rows, planned
hours, and completion credit are not copied into Phase B. P9-11 through P9-15
remain unfinished and do not inherit P9-08 through P9-10 completion evidence.

## 6. Authoritative P9-to-Phase-B mapping

| Legacy task | Historical status | Active Phase B replacement | Decision | Approval linkage |
| --- | --- | --- | --- | --- |
| P9-11 | Reassigned — unfinished | B4-01 through B4-04 | Reassigned | None |
| P9-12 | Retired and superseded by C05 | None | Retired | Retired APR-02 |
| P9-13 | Retired and superseded by C05 | None | Retired | Retired APR-01 through APR-04 |
| P9-14 | Merged into production UI — unfinished | B8-01 through B8-07 | Merged into production UI | None |
| P9-15 | Expanded and reordered — unfinished | B10-01 through B10-08; B11-01 through B11-05 | Expanded and reordered | None |

Each legacy task appears once in the CSV mapping. The CSV is the detailed
machine-readable register; this table is its human-readable summary.

## 7. P9-11 detailed disposition

P9-11 maps to:

- B4-01 — implement the reduced threat entity and ATT&CK model;
- B4-02 — implement bounded threat relationships and provenance;
- B4-03 — map validated STIX objects into threat knowledge; and
- B4-04 — expose safe threat metadata through existing views.

The retained scope is defensive metadata for threat actors, campaigns, malware
families, and ATT&CK techniques, including safe identifiers, aliases, lifecycle,
provenance, and bounded approved relationships. Malware samples, operational
instructions, inferred attribution from names, and unsafe payloads remain
prohibited. No advanced graph or separate unfinished Threat Entities sidebar
page is created; safe metadata integrates into Threat Feed and provenance
workflows.

P9-11 receives no completion credit. Its reassigned intent is satisfied only
when B4-01 through B4-04 meet their own reviewed implementation, migration,
testing, Git, and evidence criteria.

## 8. P9-12 detailed disposition

P9-12 and its former B6-02 through B6-04 Censys Platform mapping are retired:

- no Platform entitlement, endpoint, quota, credit, credential, adapter, mock,
  Prefect flow, or staging activation is pending; and
- public Censys ARC and Rapid Response publication metadata remains separate and
  must not be represented as Platform enrichment.

Existing public Censys research/publication collection is distinct from Censys
Platform API exposure enrichment. This mapping authorizes no scan, rescan,
probe, arbitrary lookup, endpoint editing, or raw licensed payload. APR-02 is
the approval linkage.

While approval or access is absent, the adapter may be completed and tested
offline, no live request is made, and the source reports `Need Approval`,
`Licence Required`, `Credentials Not Configured`, or `Disabled`. Missing
credentials are a configuration state, not a failed run, and no exposure result
is fabricated. P9-12 receives no completion credit and creates no future work.

## 9. P9-13 detailed disposition

P9-13 maps to:

- C05 B6-01 records paid-source retirement; and
- the official Approval Register retains APR-01 through APR-04 as retired
  historical records.

APR-01 through APR-04 require no decision. Censys Platform, VirusTotal
premium/business, Recorded Future, commercial free-tier workarounds, paid
credentials, subscription mocks, and fabricated commercial results are retired.

No vendor implementation remains mapped here. The former Censys B6-02 through
B6-04, VirusTotal B6-05 through B6-06, and Recorded Future B6-07 through B6-08
tasks are retired and superseded by C05. P9-13 receives no separate completion
or hours credit and creates no follow-up implementation.

## 10. P9-14 detailed disposition

P9-14 maps to B8-01 through B8-07 and is merged into the final production UI.
There is no parallel P9 frontend.

B8-01 removes Coming Soon items, dead controls, and production preview data.
The remaining B8 tasks implement the final operations, sources, run history,
UAE intelligence, core intelligence, reports, health, audit, and methodology
experience and harden production API schemas, validation, and exceptional
states. The exact 12-page top-level scope frozen by B0-03 remains authoritative.

P9-14 remains unfinished until every relevant visible page and control meets
its B8 acceptance criteria. It receives no separate completion or planned-hour
credit.

## 11. P9-15 detailed disposition

P9-15 maps primarily to B10-01 through B10-08, with release-evidence
continuation under B11-01 through B11-05.

B10 owns traceable OWASP/ASVS assessment; injection, browser, API, and outbound
security; AI-generated logic and fake-success review; dependencies, SBOM,
containers, logs, and secrets; and final reliability/security regression. B11
owns candidate freeze, mentor UAT, final documentation, evidence reconciliation,
and handover.

P9-15 is not a parallel independent review. No review is successful while an
evidence-backed Critical or High finding remains open, and no result is claimed
from an unrun check or unsupported summary. P9-15 receives no separate
completion or planned-hour credit.

## 12. Approval-gated behaviour

P9-12 retains APR-02. P9-13 links to APR-01 through APR-04 but does not replace
B0-05 as the decision-record owner. The mapping records decision dependencies;
it is not an approval decision.

Approval-gated work proceeds in separable states: offline design and mocked
implementation may be complete while live activation remains pending. Live use
requires the exact entitlement, licence, endpoint, credential, quota, retention,
and ownership prerequisites recorded by B0-05. Without them, no request is sent,
the capability remains accurately disabled, and no failed-run or coverage claim
is fabricated.

## 13. Duplicate wording and retirement rules

For B0-04, `Retired` means the legacy wording is no longer an active task. No
separate P9 implementation or completion event will occur. Work proceeds only
under the mapped Phase B tasks, while the legacy ID remains visible for
traceability. Retirement does not mean completion and grants neither planned
hours nor completion credit.

The Phase B Task Plan is the active plan, and this B0-04 crosswalk is the
authoritative reassignment reference. Legacy descriptions must not be scheduled,
estimated, implemented, completed, or reported separately. Accurate historical
evidence is retained. Outdated active wording is recorded for later correction
under B11-03; B0-04 does not edit those files. No mapped Phase B task is complete
merely because this crosswalk exists.

The combined search also retains generic process wording and other contextual
false positives as `Unrelated text`. Those rows have no legacy-task assignment
and require no reassignment treatment. This prevents broad terms such as
`independent review` or `frontend views` from being forced into P9-15 or P9-14.

## 14. Planned-hours reconciliation

No P9-11 through P9-15 hours are added to Phase B. Only the durations already in
the official Phase B Task Plan count.

```text
Adjusted Phase B planned hours
= official Phase B Task Plan hours
+ sum(B0-04 legacy hours added)
= official Phase B Task Plan hours + (0 + 0 + 0 + 0 + 0)
= official Phase B Task Plan hours
```

Therefore this mapping adds:

```text
0 additional planned Phase B hours
```

Old P9 planned-hour values are not reconstructed or invented. Mapping one
legacy task to several Phase B tasks does not duplicate their hours, and several
legacy concerns referenced by one Phase B task do not multiply that task's
duration.

## 15. Completion-credit reconciliation

Each active Phase B task can receive completion credit once, only after its own
definition of done is evidenced. P9-11 through P9-15 each receive zero Phase B
completion credit. P9-08 through P9-10 remain historical completions and are not
counted again.

```text
Additional Phase B completion credit
= MAP-0001 + MAP-0002 + MAP-0003 + MAP-0004 + MAP-0005
= 0 + 0 + 0 + 0 + 0
= 0
```

Approval-gated implementation and live activation may have different states;
neither state creates duplicate legacy credit.

## 16. Repository-reference inventory

At the frozen checkpoint, the required combined case-insensitive `git grep`
returned 35 tracked hits across 14 files. The inventory below contains exactly
one row per raw result: nine exact legacy-ID hits and 26 descriptive or
contextual hits. The two untracked B0-04 artifacts remain excluded so the
pre-change inventory does not become self-referential.

`Matched Term` records the expression responsible for the result. A contextual
match receives a legacy task only when its wording genuinely concerns that
task's purpose. Generic process wording is retained as `Unrelated text` with
`Legacy Task` set to `N/A`; it is not forced into P9-15 or another mapping.

| Reference ID | Legacy Task | File Path | Location | Matched Term | Current Wording | Classification | Risk | Required Treatment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REF-0001 | N/A | `AGENTS.md` | line 223 | independent review | The normal anti-loop workflow permits one independent review. | Unrelated text | None; process guidance is not legacy P9 scope. | Retain; no P9 reassignment linkage. |
| REF-0002 | P9-11 | `README.md` | line 243 | P9-11 | No P9-11 threat-entity implementation exists. | Dependency/reference requiring clarification | A reader may treat P9-11 as the future active task instead of B4. | Follow-up correction under B11-03: retain the historical boundary and point future work to B4-01 through B4-04. |
| REF-0003 | P9-11 | `backend/README.md` | line 240 | P9-11 | No P9-11 entity model is included. | Dependency/reference requiring clarification | The implementation boundary is accurate but the future owner is unstated. | Follow-up correction under B11-03: retain the historical boundary and add the B4 replacement. |
| REF-0004 | N/A | `backend/tests/test_testing_report_documentation.py` | line 47 | independent review | A documentation regression test rejects obsolete pre-review lifecycle wording. | Unrelated text | None; this is a P8-04 documentation assertion. | Retain; no P9 reassignment linkage. |
| REF-0005 | P9-11 | `docs/architecture.md` | line 246 | P9-11 | STIX validation occurs without creating P9-11 entity tables. | Historical evidence | Low; accurately describes the P9-10 foundation boundary. | Retain. |
| REF-0006 | P9-11 | `docs/architecture.md` | line 435 | P9-11 | P9-11 threat entities remain unimplemented. | Dependency/reference requiring clarification | The state is accurate but can imply P9-11 remains active. | Follow-up correction under B11-03: identify B4-01 through B4-04 as the active owner. |
| REF-0007 | P9-11 | `docs/architecture.md` | line 748 | P9-11 | P9-11 threat entities are grouped with excluded broader capabilities. | Superseded active wording | It may imply the reduced B4 metadata scope is excluded entirely. | Follow-up correction under B11-03: distinguish retained B4 metadata from removed graph and sample scope. |
| REF-0008 | N/A | `docs/b0-02-repository-ui-audit.md` | line 81 | independent review | The original 28 July P9-10 independent-review ZIP was unavailable. | Unrelated text | None; this is provenance for completed P9-10 evidence. | Retain; no P9 reassignment linkage. |
| REF-0009 | P9-11 | `docs/b0-02-repository-ui-audit.md` | line 213 | Threat Entities | The separate Threat Entities page is removed and safe metadata maps to B8-01 and B4-04. | Authoritative reassignment reference | Low; this supports the reduced integrated-view decision. | Retain as authoritative supporting scope. |
| REF-0010 | N/A | `docs/b0-02-repository-ui-audit.md` | line 321 | independent review | B0-02 artifacts were ready for independent review without implementing remediation. | Unrelated text | None; this describes B0-02 lifecycle state. | Retain; no P9 reassignment linkage. |
| REF-0011 | P9-11 | `docs/b0-02-repository-ui-inventory.csv` | line 394 | Threat Entities | The separate Threat Entities page is absent and assigned removal under B8-01. | Authoritative reassignment reference | Low; it records the repository-wide visible-scope decision. | Retain as authoritative supporting scope. |
| REF-0012 | N/A | `docs/b0-03-production-mvp-scope.md` | line 8 | independent review | B0-03 scope-freeze artifacts were ready for independent review but not approved or complete. | Unrelated text | None; this is B0-03 artifact status. | Retain; no P9 reassignment linkage. |
| REF-0013 | P9-11 | `docs/b0-03-production-mvp-scope.md` | line 352 | Threat Entities | The separate sidebar page is removed while safe metadata may integrate under B4-04. | Authoritative reassignment reference | Low; it is the frozen production-scope decision. | Retain as authoritative supporting scope. |
| REF-0014 | P9-12 | `docs/b0-03-production-mvp-scope.md` | line 386 | Censys enrichment | APR-02 keeps gated Censys enrichment disabled without entitlement and evidence. | Authoritative reassignment reference | Low; it is the frozen approval and safe-fallback rule. | Retain as authoritative supporting scope. |
| REF-0015 | N/A | `docs/b0-03-production-mvp-scope.md` | line 555 | Independent reviewer | The independent-reviewer sign-off field is Pending. | Unrelated text | None; this is a generic sign-off field. | Retain; no P9 reassignment linkage. |
| REF-0016 | N/A | `docs/b0-03-production-mvp-scope.md` | line 563 | independent review | B0-03 artifacts may be submitted for independent review without claiming mentor sign-off. | Unrelated text | None; this is B0-03 lifecycle wording. | Retain; no P9 reassignment linkage. |
| REF-0017 | N/A | `docs/b0-03-production-mvp-scope.md` | line 589 | independent review | B0-03 artifacts are ready for independent review while later evidence remains pending. | Unrelated text | None; this is B0-03 lifecycle wording. | Retain; no P9 reassignment linkage. |
| REF-0018 | N/A | `docs/b0-03-production-mvp-scope.md` | line 594 | independent review | The next-task transition follows independent review and a separately authorized Git lifecycle. | Unrelated text | None; this is B0-03 sequencing. | Retain; no P9 reassignment linkage. |
| REF-0019 | N/A | `docs/b0-03-production-mvp-scope.md` | line 599 | independent review | The immediate B0-03 action is uploading its files for independent review. | Unrelated text | None; this is B0-03 handoff wording. | Retain; no P9 reassignment linkage. |
| REF-0020 | N/A | `docs/b0-03-release-acceptance-checklist.csv` | line 2 | Independent reviewer | An independent reviewer owns evidence confirmation for the unavailable B0-01 PDF. | Unrelated text | None; this is a B0-01 evidence control. | Retain; no P9 reassignment linkage. |
| REF-0021 | N/A | `docs/b0-03-release-acceptance-checklist.csv` | line 3 | Independent reviewer | An independent reviewer owns verification of reconstructed B0-01 evidence. | Unrelated text | None; this is a B0-01 evidence control. | Retain; no P9 reassignment linkage. |
| REF-0022 | N/A | `docs/b0-03-release-acceptance-checklist.csv` | line 4 | independent-review | The original P9-10 independent-review ZIP is recorded as unavailable. | Unrelated text | None; this is provenance for completed P9-10 evidence. | Retain; no P9 reassignment linkage. |
| REF-0023 | P9-11 | `docs/b0-03-release-acceptance-checklist.csv` | line 100 | Threat Entities | The separate sidebar page is removed and only safe B4-04 metadata may remain. | Authoritative reassignment reference | Low; it is the frozen release acceptance gate. | Retain as authoritative supporting scope. |
| REF-0024 | N/A | `docs/data-sources.md` | line 510 | independent review | A future source requires licensing, bounded implementation, tests, documentation, and independent review. | Unrelated text | None; this is generic source-governance wording. | Retain; no P9 reassignment linkage. |
| REF-0025 | P9-12 | `docs/source-assessment-matrix.md` | historical line 35 | Censys enrichment | Former future Censys Active DNS assessment. | Retired historical evidence | C05 retires Platform/API enrichment. | No follow-up; retain only under the matrix supersession notice. |
| REF-0026 | P9-12 | `docs/source-assessment-matrix.md` | historical line 36 | Censys enrichment | Former future Censys threat-context assessment. | Retired historical evidence | C05 retires Platform/API enrichment and APR-02. | No follow-up; retain only under the matrix supersession notice. |
| REF-0027 | P9-13 | `docs/source-assessment-matrix.md` | historical line 56 | Commercial access | Former VirusTotal commercial assessment. | Retired historical evidence | C05 retires VirusTotal premium/business work and APR-03. | No follow-up; retain only under the matrix supersession notice. |
| REF-0028 | P9-11 | `docs/source-assessment-matrix.md` | line 61 | threat entities | Recorded Future report metadata may contain threat entities but remains manual metadata. | Historical evidence | Low; this is source-assessment context, not authority to implement an entity model. | Retain; B4 implementation remains independently governed. |
| REF-0029 | P9-13 | `docs/source-assessment-matrix.md` | historical line 66 | Commercial access | Former Recorded Future commercial assessment. | Retired historical evidence | C05 retires Recorded Future work and APR-04. | No follow-up; retain only under the matrix supersession notice. |
| REF-0030 | P9-13 | `docs/source-assessment-matrix.md` | line 84 | Commercial access | Mandiant threat-profile concepts require commercial-access verification and are not ingestion entities. | Dependency/reference requiring clarification | The general commercial boundary is accurate but is outside the three vendor implementations mapped by B0-04. | Follow-up correction under B11-03 or B11-04: retain as source-assessment context without expanding B6 implementation scope. |
| REF-0031 | P9-11 | `docs/source-integration-policy.md` | line 135 | P9-11 | The offline foundation is said not to complete P9-10 or implement P9-11 entities. | Superseded active wording | P9-10 is completed and the legacy P9-11 owner is retired. | Follow-up correction under B11-03: preserve the offline boundary and reference completed P9-10 plus active B4 work. |
| REF-0032 | P9-11 | `docs/stix-taxii-import.md` | line 15 | P9-11 | The importer does not implement P9-11 threat-entity tables. | Historical evidence | Low; it accurately limits the completed P9-10 importer. | Retain. |
| REF-0033 | P9-11 | `docs/stix-taxii-import.md` | line 156 | P9-11 | Supported threat objects are described as later P9-11 modelling preparation. | Superseded active wording | Later P9-11 could be scheduled as a parallel legacy task. | Follow-up correction under B11-03: replace the future owner with B4-01 through B4-04. |
| REF-0034 | P9-11 | `docs/stix-taxii-import.md` | line 222 | P9-11 | No P9-11 entity or normalized threat relationship is created. | Historical evidence | Low; it accurately describes the persisted-boundary state. | Retain. |
| REF-0035 | N/A | `docs/uae-classification.md` | line 73 | Frontend views | UAE frontend views derive labels from canonical confidence values. | Unrelated text | None; this documents current UAE presentation behavior, not legacy frontend-view planning. | Retain; no P9 reassignment linkage. |

### Combined-search reconciliation

| Measure | Count |
| --- | ---: |
| Total combined-search hits | 35 |
| Files containing hits | 14 |
| Exact legacy-ID hits | 9 |
| Descriptive or contextual hits | 26 |
| Historical evidence | 4 |
| Authoritative reassignment reference | 5 |
| Superseded active wording | 3 |
| Dependency/reference requiring clarification | 8 |
| Unrelated text | 15 |
| Associated with P9-11 | 14 |
| Associated with P9-12 | 3 |
| Associated with P9-13 | 3 |
| Associated with P9-14 | 0 |
| Associated with P9-15 | 0 |
| Unrelated / Legacy Task N/A | 15 |

The classification counts sum to 35, as do the five legacy-task association
counts plus the 15 unrelated rows. All nine exact P9-11 references remain
present. The 26 contextual hits are retained rather than silently excluded.
The five primary P9-to-Phase-B mappings remain unchanged, and no historical
source file listed above was modified by B0-04.

## 17. Risks prevented by the reconciliation

This crosswalk prevents:

- duplicate planned hours or completion credit;
- parallel execution of retired legacy task wording;
- a separate unfinished Threat Entities page or advanced graph;
- unsafe broadening from metadata to samples or operational instructions;
- confusion between public Censys publication collection and Platform API
  enrichment;
- live commercial requests without approval, entitlement, credentials, or
  quota;
- vendor implementation duplication inside an access-assessment task;
- a parallel frontend outside the frozen 12-page release scope;
- a narrow source review being mistaken for the required B10/B11 assurance; and
- fabricated approval, implementation, review, UAT, or completion claims.

## 18. Known limitations

1. The official workbook snapshot predates Git completion of B0-02 and B0-03.
2. B0-04 does not modify workbook statuses.
3. Original historical P9 planning artifacts may not all be available in the
   active review session.
4. Old P9 planned-hour values are not reconstructed or invented.
5. This mapping provides traceability and is not implementation evidence.
6. Approval-linked work remains pending until B0-05 records a real decision.
7. The existing Windows CRLF migration-hash limitation is unrelated and
   unchanged.
8. Inventory line numbers describe the frozen source checkpoint and may move
   when separately authorized follow-up documentation is edited.

## 19. Sign-off record

| Sign-off field | Value |
| --- | --- |
| Prepared by | Pending |
| Independent reviewer | Pending |
| Project owner | Pending |
| Reconciliation decision | Pending |
| Decision date | Pending |

No name, signature, date, approval, acceptance, or decision has been
fabricated.

## 20. B0-04 definition-of-done assessment

| Criterion | Assessment |
| --- | --- |
| Mandatory Git checkpoint | Met at `6bafc45c53aab4ef385a54eab47b195a3d2b08b7` |
| Mandatory repository and workbook sources | Inspected completely |
| Five authoritative mappings | Frozen; all replacement work remains unfinished |
| P9-08 through P9-10 | Preserved as completed historical foundations; not remapped |
| P9-11 through P9-15 | Retired as active wording and retained as unfinished traceability records |
| Approval-gated behaviour | Preserved; APR-02 and APR-01 through APR-04 remain pending decisions |
| Repository-reference inventory | All 35 combined-search hits across 14 tracked files classified exactly once |
| Planned Phase B hours added | 0 |
| Phase B completion credit added | 0 |
| Sign-off | Pending; no decision fabricated |
| CSV/Markdown reconciliation | Passed focused artifact validation against the official workbook |
| Complete-file self-review | Performed after CSV rendering; no defect found |
| Focused review ZIP | Required package prepared for independent review after final validation |
| Repository scope | Exactly the two authorized B0-04 files |
| Git writes | None authorized or performed |

Focused validation is documentation-only. Backend and frontend suites are not
run for B0-04. Exact commands, exit codes, warnings, limitations, workbook
comparison, CSV checks, complete-file review, and final Git status are recorded
in the focused archive after final validation.

The mapping artifacts do not approve or complete B0-04 or any replacement task.
The artifacts and focused archive are ready to submit for independent review;
review, approval, staging, and completion remain pending.

## 21. Exact next task: B0-05

After independent review, any separately authorized staging/commit lifecycle,
and confirmation that this reconciliation remains accurate, the exact next
Phase B task is B0-05 — prepare and obtain mentor decisions. B0-05 has not been
started in this work unit.

Immediate next action: upload the focused B0-04 ZIP and both complete files for
independent review before any staging or commit.
