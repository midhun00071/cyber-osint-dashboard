# B0-05 Mentor Decision and Approval Pack

> **C05 supersession (5 August 2026):** APR-01 through APR-04 and every request
> below for Censys Platform/API, VirusTotal premium/business, Recorded Future,
> paid credentials, licences, subscriptions, or commercial access are retired.
> They are retained only as historical decision-pack evidence and require no
> mentor response. No commercial adapter, mock, credential request, or later
> activation remains in the production plan. Public Censys publication metadata
> remains a separate public workflow.

## 1. Document control

| Field | Value |
| --- | --- |
| Task | B0-05 — Prepare and obtain mentor decisions |
| Artifact status | Mentor-decision artifacts ready for independent review; no decision approved |
| Preparation date | 30 July 2026 |
| Branch | `dev` |
| Source checkpoint | `b0a7dc8b4858eb4b1417a13f4b8430cc4423395b` |
| Source commit | `b0a7dc8 B0-04 Reassign unfinished P9 work` |
| Formal dependency | B0-03 completed |
| Active P9 reconciliation | B0-04 completed, reviewed, committed and pushed |
| Official source | Phase B workbook `Approval Register!A1:H16` and `Task Plan!A1:V75` |
| Authoritative repository register | `docs/b0-05-approval-register.csv` |
| Submission deadline | 11 August 2026 |

This pack prepares decision requests; it does not supply, infer or approve a
decision. No current feature, adapter, configuration field or document proves
organisational approval.

## 2. Task, dependency and checkpoint

The mandatory gate passed before source inspection or artifact creation:

- branch was exactly `dev`;
- the working tree was clean;
- `git fetch origin` succeeded;
- local `HEAD` and refreshed `origin/dev` both equalled
  `b0a7dc8b4858eb4b1417a13f4b8430cc4423395b`;
- the latest commit was `B0-04 Reassign unfinished P9 work`; and
- B0-03 and the active B0-04 reconciliation were present.

No pull, branch switch, stage, commit, push, reset, restore, clean, repository
file deletion or history rewrite is authorised or performed by B0-05.

## 3. Purpose and decision boundary

The pack covers APR-01 through APR-15 and gives an authorised mentor or owner
the information needed to decide budget, source access, automation, scheduling,
hosting, TLS, data storage, secrets, backup, monitoring, user access, SSO and
final release acceptance. Development may continue offline where a stated safe
fallback exists.

B0-05 does not contact vendors, use credentials, create accounts or users,
enable integrations or collectors, schedule production work, deploy staging,
configure SSO or approve release. Until attributable evidence is recorded,
every approval remains `Need Approval` and its fallback remains active.

## 4. Instructions for the mentor

For each approval:

1. select one permitted option or describe a narrower authorised decision;
2. confirm the decision-maker name or authorised role outside secret fields;
3. record the real decision date, limits, conditions and evidence reference;
4. give any review or expiry date; and
5. use an approved secure channel for credential delivery when applicable.

Do not place a decision in `Approved`, `Approved with Conditions`, `Rejected`,
`Deferred` or `Not Required` without direct evidence from an authorised
decision-maker. A fallback is not approval.

## 5. Security rules for supplying decisions and credentials

- Do not paste credentials into ChatGPT, Git, the workbook or documentation.
- Do not email secrets in plain text.
- Do not record passwords, password hashes, full tokens, private keys,
  certificates with private material, database URLs, cookies or auth headers.
- Record only the credential-owner role, approved delivery mechanism,
  secret-reference identifier and rotation expectation.
- Use an organisational secret manager or approved secure staging delivery
  method.
- Redact screenshots and avoid raw vendor responses containing account, quota
  or entitlement identifiers.
- Store evidence references rather than sensitive evidence contents.
- Preserve an auditable history; do not silently replace an older decision.
- Record a changed decision with a new date and evidence reference.

## 6. Decision-status vocabulary

Only these values are permitted:

| Status | Meaning |
| --- | --- |
| Need Approval | No attributable decision evidence is recorded; fallback remains active. |
| Approved | An authorised decision fully permits the recorded bounded scope. |
| Approved with Conditions | An authorised decision permits only the recorded limits and residual conditions. |
| Rejected | An authorised decision refuses the requested scope. |
| Deferred | An authorised decision postpones the decision; fallback remains active. |
| Not Required | An authorised decision confirms the approval is not applicable. |

All 15 rows currently use `Need Approval` because no mentor response was
supplied during this task.

## 7. Decision-summary dashboard

The counts below are derived from the accompanying 15-row CSV register:

| Measure | Count or scope |
| --- | --- |
| Total approvals | 15 |
| Need Approval | 15 |
| Approved | 0 |
| Approved with Conditions | 0 |
| Rejected | 0 |
| Deferred | 0 |
| Not Required | 0 |
| Decisions needed by 4 August 2026 | 10; APR-01 through APR-04 retired by C05 |
| Final decision needed by 11 August 2026 | 1 |
| Commercial/vendor approvals | Retired historical records APR-01 through APR-04 |
| UAE automation approval | APR-05 |
| Scheduling approval | APR-06 |
| Hosting and operational approvals | APR-07 through APR-12 |
| Access and identity approvals | APR-13 and APR-14 |
| Final release approval | APR-15 |

## 8. APR-01 retired historical record

| Field | Request |
| --- | --- |
| Decision requested | None. C05 retired the commercial account, licence, subscription, and budget work. |
| Decision owner role | Mentor / project owner with budget and vendor authority |
| Needed by | 4 August 2026 |
| Related tasks | None; former paid-source tasks retired by C05 |
| Why required | Live commercial access may require paid licences or credits. |
| Permitted options | Approved accounts and bounded budget available; Some vendors approved; No commercial access for this release; Decision deferred |
| Recommended secure default | No live commercial calls until vendor-specific approval is recorded. |
| Limits and conditions to record | Vendor, account ownership, licence, permitted use, budget, quota, retention, credential-owner role and expiry. |
| Required evidence | Attributable budget/account decision plus vendor-specific entitlement references; no secret values. |
| Release-safe fallback | Complete adapters offline; show accurate Need Approval/Licence Required state. |
| What remains disabled | Live calls and paid-source coverage for all unapproved vendors. |
| Consequence if unanswered | Staging may proceed only with all affected live features disabled, tested offline fallbacks and truthful UI/documentation. |
| Prohibited claims | No live Censys, VirusTotal or Recorded Future coverage claim. |
| Current status | Retired and superseded by C05 |

```text
Approval ID: APR-01
Decision status: Retired
Decision-maker: Not required
Decision date: 2026-08-05
Decision: Superseded by C05 paid-source retirement
Limits and conditions: No commercial implementation remains planned
Evidence reference: docs/c05-official-public-sources.md
Review or expiry date: Not applicable
Additional notes: Historical record only; no response required
```

## 9. APR-02 retired historical record

| Field | Request |
| --- | --- |
| Decision requested | None. C05 retired Censys Platform/API implementation and activation work. |
| Decision owner role | Mentor / project owner and named organisational credential owner |
| Needed by | 4 August 2026 |
| Related tasks | B6-02 through B6-04 |
| Why required | Public research access does not establish Platform API entitlement. |
| Permitted options | Approved for fixed-policy staging use; Approved with endpoint, field or credit limits; Not approved; Deferred |
| Recommended secure default | Keep live enrichment disabled. |
| Limits and conditions to record | Product entitlement, exact endpoints, fields, credits, retention, token-owner role, secret reference and rotation. |
| Required evidence | Entitlement record, fixed-policy boundary, quota approval and secure credential-delivery reference. |
| Release-safe fallback | Censys adapter complete with mocks; live disabled. |
| What remains disabled | Censys Platform live enrichment. |
| Consequence if unanswered | Staging may proceed only with mocked verification, live enrichment disabled and an accurate disabled state. |
| Prohibited claims | Public Censys publication collection must not be represented as Censys Platform enrichment. |
| Current status | Retired and superseded by C05 |

```text
Approval ID: APR-02
Decision status: Retired
Decision-maker: Not required
Decision date: 2026-08-05
Decision: Superseded by C05 paid-source retirement
Limits and conditions: Public Censys publication metadata remains distinct
Evidence reference: docs/c05-official-public-sources.md
Review or expiry date: Not applicable
Additional notes: Historical record only; no response required
```

## 10. APR-03 retired historical record

| Field | Request |
| --- | --- |
| Decision requested | None. C05 retired VirusTotal premium/business and free-tier workaround work. |
| Decision owner role | Mentor / project owner and named organisational credential owner |
| Needed by | 4 August 2026 |
| Related tasks | B6-05 through B6-06 |
| Why required | Public or community access may not permit company production use. |
| Permitted options | Metadata-only staging use approved; Approved with quotas and field restrictions; Not approved; Deferred |
| Recommended secure default | Keep live requests disabled. |
| Limits and conditions to record | Permitted business use, tier, endpoints, fields, quota, retention, redistribution, credential owner, secret reference and rotation. |
| Required evidence | Licence/tier decision, permitted-field and quota record, retention rule and secure credential reference. |
| Release-safe fallback | Metadata adapter complete; live disabled. |
| What remains disabled | Live metadata requests. File upload, malware sample submission and binary retrieval remain absolutely prohibited. |
| Consequence if unanswered | Staging may proceed only with the offline adapter tested and all live requests disabled. |
| Prohibited claims | No live VirusTotal enrichment, file-upload, malware-submission, sample-retrieval or binary-retrieval claim. |
| Current status | Retired and superseded by C05 |

```text
Approval ID: APR-03
Decision status: Retired
Decision-maker: Not required
Decision date: 2026-08-05
Decision: Superseded by C05 paid-source retirement
Limits and conditions: No VirusTotal integration remains planned
Evidence reference: docs/c05-official-public-sources.md
Review or expiry date: Not applicable
Additional notes: Historical record only; no response required
```

## 11. APR-04 retired historical record

| Field | Request |
| --- | --- |
| Decision requested | None. C05 retired Recorded Future subscription and integration work. |
| Decision owner role | Mentor / project owner and named organisational credential owner |
| Needed by | 4 August 2026 |
| Related tasks | B6-07 through B6-08 |
| Why required | Live endpoints depend on organisational entitlement. |
| Permitted options | Approved licensed modules; Approved with endpoint or quota restrictions; Not approved; Deferred |
| Recommended secure default | Keep live requests disabled. |
| Limits and conditions to record | Licensed modules, endpoints, fields, quota, storage, retention, redistribution, credential owner, secret reference and rotation. |
| Required evidence | Subscription/module decision, permitted-use boundary, quota and secure credential reference. |
| Release-safe fallback | Safe mocked adapter complete; live disabled. |
| What remains disabled | Recorded Future live requests and licensed-data coverage. |
| Consequence if unanswered | Staging may proceed only with the safe mocked adapter and truthful `Licence Required` state. |
| Prohibited claims | No Recorded Future data-coverage claim. |
| Current status | Retired and superseded by C05 |

```text
Approval ID: APR-04
Decision status: Retired
Decision-maker: Not required
Decision date: 2026-08-05
Decision: Superseded by C05 paid-source retirement
Limits and conditions: No Recorded Future integration remains planned
Evidence reference: docs/c05-official-public-sources.md
Review or expiry date: Not applicable
Additional notes: Historical record only; no response required
```

## 12. APR-05 decision request

| Field | Request |
| --- | --- |
| Decision requested | Approve automation separately for each proposed UAE public source after terms, robots and source-policy review. |
| Decision owner role | Mentor / project owner, with organisational legal or policy review where required |
| Needed by | 4 August 2026 |
| Related tasks | B5-01 through B5-04 |
| Why required | Public accessibility does not automatically authorise scheduled collection. |
| Permitted options | Approve named sources individually; Approve with cadence, path or field restrictions; Manual-only use; Not approved; Deferred |
| Recommended secure default | Keep every unapproved collector disabled. |
| Limits and conditions to record | One record per source: HTTPS host, paths, cadence, fields, terms and robots basis, redirects, retention, owner and review date. |
| Required evidence | Source-specific policy decision naming the approved host, paths, cadence, fields and policy basis. |
| Release-safe fallback | Fixture-tested collectors remain disabled. |
| What remains disabled | Every UAE automated collector without a source-specific approval record. |
| Consequence if unanswered | Staging may proceed only with affected collectors disabled and fixtures or mocked collectors tested. |
| Prohibited claims | No automated UAE-source coverage claim while collectors are disabled. |
| Current status | Need Approval |

```text
Approval ID: APR-05
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 13. APR-06 decision request

| Field | Request |
| --- | --- |
| Decision requested | Confirm whether a two-hour production schedule is authorised, the applicable timezone and the operations owner. |
| Decision owner role | Mentor / project owner and staging operations owner |
| Needed by | 4 August 2026 |
| Related tasks | B2-03 |
| Why required | Recurring collection creates traffic, quota use and operational responsibility. |
| Permitted options | Approve every two hours in an explicit timezone; Approve staging rehearsal only; Approve a different bounded cadence; Not approved; Deferred |
| Recommended secure default | Controlled staging only, with unapproved sources disabled. |
| Limits and conditions to record | Timezone, cadence, owner, enabled-source set, overlap policy, retry/backoff bounds, pause authority and evidence window. |
| Required evidence | Attributable schedule decision naming timezone, cadence, owner, enabled sources and overlap policy. |
| Release-safe fallback | Schedule enabled in controlled staging only. |
| What remains disabled | Recurring production scheduling and every source lacking its own prerequisites; manual flows remain available. |
| Consequence if unanswered | Staging may proceed through manual flows and only an explicitly approved controlled rehearsal; it cannot claim a production schedule. |
| Prohibited claims | No production-schedule claim without approval. |
| Current status | Need Approval |

```text
Approval ID: APR-06
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 14. APR-07 decision request

| Field | Request |
| --- | --- |
| Decision requested | Select the staging hosting provider, environment owner and mentor access method. |
| Decision owner role | Mentor / project owner and infrastructure owner |
| Needed by | 4 August 2026 |
| Related tasks | B9-03 |
| Why required | Mentor-accessible staging requires owned infrastructure. |
| Permitted options | Approved hosted staging; Approved internal host or VM; Approved temporary controlled host; Local demonstration fallback accepted; Deferred |
| Recommended secure default | No public deployment until ownership and access are defined. |
| Limits and conditions to record | Provider or host class, environment owner, access route, authentication boundary, network exposure, shutdown owner and support window. |
| Required evidence | Hosting decision and access architecture, or explicit mentor acceptance of the documented local fallback. |
| Release-safe fallback | Documented local Docker deployment. |
| What remains disabled | Public or remote staging deployment and mentor access outside the documented local environment. |
| Consequence if unanswered | Staging release proceeds only if the mentor explicitly accepts the local or controlled fallback; otherwise it cannot proceed. |
| Prohibited claims | No mentor-accessible hosted-staging or production-deployment claim. |
| Current status | Need Approval |

```text
Approval ID: APR-07
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 15. APR-08 decision request

| Field | Request |
| --- | --- |
| Decision requested | Confirm the approved hostname and certificate or TLS owner. |
| Decision owner role | Mentor / project owner and domain/TLS administrator |
| Needed by | 4 August 2026 |
| Related tasks | B9-02 |
| Why required | Secure routing requires controlled naming and certificate management. |
| Permitted options | Approved domain/subdomain and certificate owner; Approved internal hostname; Temporary controlled host with TLS-ready configuration; Local-only fallback; Deferred |
| Recommended secure default | Do not expose plain HTTP to untrusted networks. |
| Limits and conditions to record | Hostname, owner role, DNS authority, renewal responsibility, certificate delivery, TLS termination and review date. |
| Required evidence | Hostname/ownership decision and certificate-delivery reference; no private key. |
| Release-safe fallback | Local TLS-ready reverse proxy and host-file access. |
| What remains disabled | Public hostname, external routing and certificate activation; plain HTTP to untrusted networks remains prohibited. |
| Consequence if unanswered | Staging may proceed only through the local TLS-ready fallback without a public-hostname or active-TLS claim. |
| Prohibited claims | No approved-domain, active-TLS or secure-public-routing claim. |
| Current status | Need Approval |

```text
Approval ID: APR-08
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 16. APR-09 decision request

| Field | Request |
| --- | --- |
| Decision requested | Select the PostgreSQL hosting model, operational owner, retention period and storage constraints. |
| Decision owner role | Mentor / project owner and database/infrastructure owner |
| Needed by | 4 August 2026 |
| Related tasks | B1-05 and B9-03 |
| Why required | Availability, backup, data lifecycle and cost depend on these decisions. |
| Permitted options | Approved managed PostgreSQL; Approved self-hosted staging PostgreSQL; Approved with retention limits; Deferred |
| Recommended secure default | Self-hosted staging with conservative bounded retention. |
| Limits and conditions to record | Host class, owner, retention, storage limit, backup boundary, least-privilege roles, encryption and maintenance responsibility. |
| Required evidence | Hosting and retention decision, owner, least-privilege role boundary and accepted fallback evidence; no database URL. |
| Release-safe fallback | Self-hosted staging PostgreSQL with conservative retention. |
| What remains disabled | Managed or production database hosting, unapproved retention and unsupported availability or durability claims. |
| Consequence if unanswered | Staging release proceeds only if the mentor explicitly accepts the self-hosted fallback, owner and retention boundary; otherwise it cannot proceed. |
| Prohibited claims | No approved production-hosting, retention, availability or recovery claim. |
| Current status | Need Approval |

```text
Approval ID: APR-09
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 17. APR-10 decision request

| Field | Request |
| --- | --- |
| Decision requested | Select the approved secret-management method and credential-delivery process. |
| Decision owner role | Mentor / project owner and security/infrastructure owner |
| Needed by | 4 August 2026 |
| Related tasks | B1-01 and B9-04 |
| Why required | Production credentials require secure organisational handling. |
| Permitted options | Approved organisational secret manager; Approved Docker or platform-independent secret files or references for staging; No live paid credentials for this release; Deferred |
| Recommended secure default | No live secret value is supplied until the delivery mechanism is approved. |
| Limits and conditions to record | Provider/mechanism, owner role, reference convention, delivery route, access policy, rotation and revocation expectations. |
| Required evidence | Approved provider or mechanism, owner, reference-name convention, rotation requirement and delivery procedure. |
| Release-safe fallback | Docker secret references; no live paid credentials. |
| What remains disabled | Live paid credentials, commercial integrations and production secret delivery. |
| Consequence if unanswered | Staging may proceed only with secret references and dependent live integrations disabled. |
| Prohibited claims | Never record or claim approval for secret values in the register, chat, Git, workbook or documentation. |
| Current status | Need Approval |

```text
Approval ID: APR-10
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 18. APR-11 decision request

| Field | Request |
| --- | --- |
| Decision requested | Select the approved backup destination, retention and owner. |
| Decision owner role | Mentor / project owner and backup/storage owner |
| Needed by | 4 August 2026 |
| Related tasks | B9-05 |
| Why required | Off-host recovery requires approved storage and lifecycle controls. |
| Permitted options | Approved encrypted off-host destination; Approved controlled internal storage; Local encrypted rehearsal only; Deferred |
| Recommended secure default | Encrypted local rehearsal backup without a production-recovery claim. |
| Limits and conditions to record | Destination class, owner, retention, encryption, access control, deletion, restore cadence, RPO, RTO and review date. |
| Required evidence | Destination/owner decision, encryption and access-control record, deletion procedure and restore-test evidence reference. |
| Release-safe fallback | Encrypted local rehearsal backup. |
| What remains disabled | Production off-host backup, scheduled retention and production recoverability claims. |
| Consequence if unanswered | Staging may proceed only with an implemented and tested encrypted local rehearsal and no production-recovery claim. |
| Prohibited claims | No approved production-backup, off-host-retention, RPO, RTO or recoverability claim. |
| Current status | Need Approval |

```text
Approval ID: APR-11
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 19. APR-12 decision request

| Field | Request |
| --- | --- |
| Decision requested | Select the operational monitoring method and authorised alert recipient. |
| Decision owner role | Mentor / project owner and staging operations owner |
| Needed by | 4 August 2026 |
| Related tasks | B9-04 |
| Why required | Alerts require ownership and may require paid tooling. |
| Permitted options | Approved provider and recipient; Self-hosted logs and health checks; No external alerting for staging; Deferred |
| Recommended secure default | Self-hosted logs and health checks with a named review-owner role. |
| Limits and conditions to record | Monitoring method, owner role, recipient role/channel reference, thresholds, retention, escalation, quiet hours and review date. |
| Required evidence | Provider/method decision, authorised recipient reference, alert ownership and escalation procedure; no webhook or token. |
| Release-safe fallback | Self-hosted logs and health checks. |
| What remains disabled | External operational alert delivery and paid monitoring integration. Product Slack, Teams or email notifications are not authorised by APR-12. |
| Consequence if unanswered | Staging may proceed using self-hosted logs and health checks only when review ownership is explicit. |
| Prohibited claims | No external operational-alerting or product Slack, Teams or email-alert feature claim. |
| Current status | Need Approval |

```text
Approval ID: APR-12
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 20. APR-13 decision request

| Field | Request |
| --- | --- |
| Decision requested | Confirm authorised staging users and acceptance of the local RBAC model. |
| Decision owner role | Mentor / project owner |
| Needed by | 4 August 2026 |
| Related tasks | B7-01 |
| Why required | Accounts and access must be explicitly authorised. |
| Permitted options | Approve named users and roles; Approve role model but defer final user list; Require changes; Deferred |
| Recommended secure default | Create only minimal mentor and team accounts after approval. |
| Limits and conditions to record | User identity reference, assigned role, approver role, account expiry and revocation owner; no passwords or hashes. |
| Required evidence | Attributable role-model decision and authorised user list, or explicit mentor acceptance of the restricted local fallback. |
| Release-safe fallback | Minimal mentor/team accounts created securely. |
| What remains disabled | User provisioning, shared/default accounts and access by unauthorised users. B0-05 creates no users. |
| Consequence if unanswered | Staging release proceeds only if the mentor explicitly accepts restricted local access and authorises the minimal user/role set; otherwise it cannot proceed. |
| Prohibited claims | No authorised-staging-user, accepted-RBAC or mentor-access claim. |
| Current status | Need Approval |

```text
Approval ID: APR-13
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 21. APR-14 decision request

| Field | Request |
| --- | --- |
| Decision requested | Confirm whether company SSO is required for the staging release. |
| Decision owner role | Mentor / project owner and identity administrator where applicable |
| Needed by | 4 August 2026 |
| Related tasks | B7-01 |
| Why required | Identity-provider integration may require organisational configuration. |
| Permitted options | SSO required and configuration will be supplied; SSO not required for staging and secure local RBAC accepted; SSO deferred post-submission; Decision pending |
| Recommended secure default | Secure local RBAC remains required regardless of SSO. |
| Limits and conditions to record | SSO requirement, provider-owner role, protocol, configuration-delivery mechanism, local-RBAC acceptance and review date. |
| Required evidence | Attributable SSO/local-RBAC decision and identity configuration reference; no client secret. |
| Release-safe fallback | Secure local RBAC; SSO-ready interface. |
| What remains disabled | SSO integration and every SSO capability claim; secure local RBAC remains required. |
| Consequence if unanswered | Staging may proceed only with secure local RBAC and no SSO claim. |
| Prohibited claims | No SSO-support claim without implementation and evidence. |
| Current status | Need Approval |

```text
Approval ID: APR-14
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 22. APR-15 final-release decision request

| Field | Request |
| --- | --- |
| Decision requested | Explicitly accept or reject the exact deployed scope, disabled approval-gated sources, accepted limitations and residual risk. |
| Decision owner role | Mentor / release approver |
| Needed by | 11 August 2026 |
| Related tasks | B11-02 and B11-05 |
| Why required | The release cannot approve itself. |
| Permitted options | Release accepted; Accepted with recorded conditions; Rejected pending remediation; Deferred |
| Recommended secure default | No release without explicit sign-off. |
| Limits and conditions to record | Exact candidate commit, UAT record, unresolved findings, limitations, disabled sources, decision scope, approver, date and conditions. |
| Required evidence | Release-candidate commit, mentor UAT, findings, accepted limitations, disabled-source list and immutable decision reference. |
| Release-safe fallback | No release without explicit sign-off record. |
| What remains disabled | Final release and every release-acceptance or residual-risk-acceptance claim. |
| Consequence if unanswered | Release cannot proceed. There is no self-approved or automatic fallback. |
| Prohibited claims | No release acceptance, mentor UAT acceptance, residual-risk acceptance or final sign-off claim. |
| Current status | Need Approval; APR-15 cannot be approved during B0-05. |

```text
Approval ID: APR-15
Decision status: Need Approval
Decision-maker: Pending
Decision date: Pending
Decision: Pending
Limits and conditions: Pending
Evidence reference: Pending
Review or expiry date: Pending
Additional notes: Pending
```

## 23. Cost and licence implications

| Approval group | Potential implication |
| --- | --- |
| APR-01 through APR-04 | Retired historical commercial records; no subscription, tier, module, credit, quota, credential, or cost decision is requested. |
| APR-05 and APR-06 | Source-policy review, traffic, quotas, compute and operational ownership may create indirect cost. |
| APR-07 through APR-12 | Hosting, domain/TLS, database, secret-management, backup, monitoring, storage, transfer and support choices may create recurring infrastructure cost. |
| APR-13 and APR-14 | Identity administration, account lifecycle and an external identity provider may create administration or licence cost. |
| APR-15 | The decision itself has no vendor cost, but remediation, hosting and operational conditions may affect release cost. |

No budget or entitlement is inferred. APR-01 is the common commercial budget
gate; vendor-specific terms still require APR-02, APR-03 or APR-04.

## 24. Release-safe fallback summary

Subject to every other release gate, staging may proceed without approval for
APR-01 through APR-06, APR-08, APR-10 through APR-12 and APR-14 only when the
relevant live or paid feature remains disabled, its stated fallback is
implemented and tested, UI/documentation show the truth, no unsupported claim
is made and no secret or live request is used.

APR-07, APR-09 and APR-13 require either an approved operational decision or an
explicit mentor acceptance of the documented local or controlled fallback.
Silence is not acceptance. APR-15 has no release fallback: release cannot
proceed without explicit authorised sign-off.

## 25. Disabled-state and truthfulness requirements

- Commercial vendor integrations remain disabled without account, licence,
  permitted-use, endpoint, quota and credential evidence.
- Unapproved UAE automated collectors remain disabled.
- Production scheduling remains disabled; a controlled rehearsal requires its
  own explicit authority.
- Public hosting, domain activation and external TLS claims remain disabled or
  absent without owners and evidence.
- Unapproved database, secret, backup and external-monitoring capabilities
  remain restricted to their documented fallbacks.
- User provisioning and SSO remain disabled without explicit access decisions.
- Final release remains blocked by APR-15.
- A disabled, mocked, local or rehearsal state must never be presented as live,
  approved, production-ready or mentor-accepted.

## 26. How to record a real decision

A valid update must record the approval ID, permitted status, authorised
decision-maker name or role, real date, decision details, limits, related tasks,
evidence reference, residual conditions and any review or expiry date. For a
credential decision, record only the named owner, approved delivery mechanism,
secret-reference identifier and rotation expectation.

Update the register through a separately reviewed change. Preserve prior
decision history, cite the new evidence and date, and never overwrite an older
decision silently. Do not treat an email, code path, environment variable,
existing adapter or fallback as approval unless the authorised decision record
explicitly says so.

## 27. Pending decisions and deadline risks

Ten unrelated decisions remain from the original 4 August 2026 target. APR-01
through APR-04 no longer require decisions, and paid sources remain retired.
Other pending decisions can keep UAE automation, scheduling, hosting, TLS,
database operations, secrets, backup, monitoring, user access, or SSO disabled
and can force a documented local-only or offline demonstration. APR-07, APR-09
and APR-13 need explicit acceptance of
even their local fallback before staging release can rely on it.

APR-15 is due by 11 August 2026 and depends on an exact release candidate,
mentor UAT and residual-risk evidence that do not yet exist. If APR-15 remains
unanswered, release cannot proceed or be described as accepted.

## 28. Known limitations

1. No mentor decisions were supplied during this Codex task.
2. All APR-01 through APR-15 statuses therefore remain `Need Approval`.
3. These artifacts prepare decision requests but cannot independently obtain
   organisational approval.
4. No vendor account, licence, budget, credential, endpoint entitlement or
   quota was verified.
5. No hosting, domain, TLS, database, secret-manager, backup or monitoring
   provider was approved.
6. No staging user was authorised.
7. No SSO requirement was decided.
8. APR-15 cannot be completed until the release candidate and mentor UAT exist.
9. The workbook snapshot predates Git completion of B0-02 through B0-04.
10. B0-05 must not delay safe offline implementation where an explicit fallback
    exists.
11. The existing Windows CRLF migration-hash limitation is unrelated and
    unchanged.

## 29. Sign-off and decision record

| Field | Value |
| --- | --- |
| Prepared by | Pending |
| Independent reviewer | Pending |
| Project owner | Pending |
| Mentor / release approver | Pending |
| Review date | Pending |
| Overall decision | Pending |
| Evidence reference | Pending |

No approval, approver, decision, account, licence, credential, budget,
signature, date or evidence has been fabricated. Individual decisions must be
recorded in their response block and the CSV before any summary status changes.

## 30. B0-05 definition-of-done assessment

| Criterion | Assessment |
| --- | --- |
| Mandatory Git checkpoint | Met at `b0a7dc8b4858eb4b1417a13f4b8430cc4423395b` |
| Required repository and workbook sources | Inspected completely |
| APR-01 through APR-15 | All 15 represented once |
| Owner roles and needed-by dates | Recorded for all 15; no person invented |
| Options, defaults and fallback | Recorded for all 15 |
| Disabled state, consequence and prohibited claim | Recorded for all 15 |
| Current approval statuses | 15 `Need Approval`; all other status counts zero |
| Pending decision fields | Preserved as `Pending` |
| Sensitive values | Excluded; secure reference-only handling documented |
| CSV and Markdown reconciliation | Passed focused validation against the official workbook |
| Complete-file review | Performed after rendering; no defect identified |
| Focused review ZIP | Required package prepared after final validation |
| Repository scope | Exactly the two authorised B0-05 files |
| Git writes | None authorised or performed |

Artifact-level preparation does not mean a mentor approved any decision and
does not make B0-05 approved or complete. The artifacts and archive are ready
for independent review; approval, staging, commit and task completion remain
pending.

## 31. Exact next task: B0-06

After independent review and any separately authorised staging/commit lifecycle,
the exact next task is B0-06 — Create production architecture and threat model.
B0-06 is not started in this work unit.

Immediate next action: upload the focused B0-05 ZIP and both complete files for
independent review before any staging or commit.
