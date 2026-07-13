# UAE Relevance Classification

## Purpose

P4-01 added deterministic offline classification for whether a normalized
public cybersecurity intelligence record contains direct UAE-related evidence.
P4-02 adds a fixed deterministic confidence mapping for automatic rule results.

UAE relevance classification identifies whether a public cybersecurity
intelligence record contains direct UAE-related evidence. The confidence value
represents the strength of deterministic evidence used for UAE relevance
classification. It does not represent exploit probability, threat attribution,
attacker intent, targeting certainty, or business impact.

## Inputs

The classifier uses only safe normalized metadata already controlled by the
application:

- normalized title;
- normalized summary or description;
- controlled source slugs;
- existing normalized geographic scope.

It does not inspect raw upstream payloads, headers, credentials, environment
values, or arbitrary user input.

## Rule Order

Rules are evaluated from strongest to weakest:

1. approved UAE cybersecurity or government source slug;
2. direct country phrase: `United Arab Emirates`;
3. standalone UAE acronym, including safe `UAE` and `U.A.E.` variants;
4. direct emirate name;
5. no direct UAE evidence.

The strongest matching rule wins. Direct country, acronym, emirate, and
approved-source matches set `geographic_scope=uae`,
`uae_relevance_status=confirmed`, and `uae_relevance_method=automatic`.

When no direct UAE evidence is found, the classifier preserves the existing
geographic scope and sets `uae_relevance_status=unknown` with an automatic
explanation. It does not mark non-matches as definitively not relevant.

## Rule-Strength Confidence

Automatic classifier confidence is stored in `uae_relevance_confidence` as a
nullable `numeric(4,3)` database value between `0.000` and `1.000`, and is
serialized by the read-only APIs as a JSON number or `null`.

The mapping is intentionally small and fixed:

| Rule ID | Confidence | Meaning |
|---|---:|---|
| `approved_uae_source` | `0.950` | Approved UAE cybersecurity or government source identity. |
| `direct_country_name` | `0.950` | Direct `United Arab Emirates` phrase in one safe text field. |
| `direct_uae_acronym` | `0.900` | Standalone `UAE` or safe `U.A.E.` variant in one safe text field. |
| `direct_emirate_name` | `0.850` | Direct emirate name in one safe text field. |
| `no_direct_uae_evidence` | `null` | No affirmative direct UAE evidence rule matched. |

`null` means no automatic confidence was assigned because no direct UAE
evidence rule matched. It does not mean the item was proven to have zero UAE
relevance.

Repeated mentions do not increase confidence. Generic regional phrases, sector
terms, severity, CVSS, EPSS, KEV status, article length, and arbitrary source
names do not contribute to UAE relevance confidence. The strongest P4-01 rule
determines both the automatic status and confidence.

## UI Confidence Labels

Frontend views derive clear presentation labels from the canonical numeric
confidence value:

| Label | Numeric range |
|---|---|
| High | `0.900`-`1.000` |
| Medium | `0.750`-`0.899` |
| Low | `0.000`-`0.749` |
| No label | `null` |

Examples include `Confirmed · High confidence (95%)`,
`Confirmed · Medium confidence (85%)`, and
`Possible · Low confidence (40%)`. When confidence is `null`, the UI displays
only the relevance status, such as `Unknown`.

These labels are presentation levels derived from the backend numeric value.
They are not threat severity, exploit probability, statistical calibration,
attribution certainty, targeting certainty, or business impact. Low confidence
does not automatically mean an item is not relevant. The current automatic
rules emit High or Medium values; Low remains valid for manually reviewed,
source-declared, seeded, or future confidence metadata.

## Trusted Source Allow-List

Trusted-source classification uses only explicit canonical source slugs:

- `ae-cert`
- `uae-cert`
- `uae-cyber-security-council`

The classifier does not trust source display names, arbitrary URLs, article
text claiming official status, or substring look-alikes.

## Text Normalization

Text is normalized with Unicode NFKC, case folding, punctuation-safe separators
including underscores, collapsed whitespace, and bounded input length. Title and
summary are evaluated independently so direct phrases cannot match across field
boundaries. Regex rules are static and are not compiled from user input.

## False-Positive Controls

Regional terms alone are insufficient:

- Middle East
- Gulf
- GCC
- MENA
- Arabian Gulf

Sector terms alone are also insufficient:

- banking
- finance
- oil
- gas
- energy
- aviation
- telecommunications
- government
- critical infrastructure

The standalone `UAE` rule uses token boundaries and does not match unrelated
words that merely contain the letters `uae`.

## Ownership Protection

Automatic classification updates only records whose current method is
`unassigned` or `automatic`. Records marked `manual` or `source_declared`, and
records with unknown non-empty methods, are preserved.

Protected records preserve status, geographic scope, confidence, reason, and
method. Automatic recalculation is limited to records currently marked
`unassigned` or `automatic`.

NVD updates, CERT-EU RSS updates, FIRST EPSS enrichment, CISA KEV enrichment,
duplicate handling, and conflict handling must not overwrite protected
classification data.

## Manual CLI

Dry-run is the default:

```powershell
Push-Location .\backend
.\.venv\Scripts\python.exe -m app.processing.uae_classification_cli --max-items 20
Pop-Location
```

Persistent changes require `--apply`:

```powershell
Push-Location .\backend
.\.venv\Scripts\python.exe -m app.processing.uae_classification_cli --max-items 20 --apply
Pop-Location
```

The CLI validates the item limit, imposes a hard upper bound, prints sanitized
counts, and does not expose internal database IDs. Dry-run output includes
records that would change only because confidence would be added or corrected.
Persistent confidence backfill still requires explicit `--apply`.

## Ingestion and API Behavior

New NVD and CERT-EU RSS records receive the mapped automatic confidence when
the classifier assigns a direct UAE relevance rule. Eligible automatic records
updated by those ingestion services are recalculated from the same centralized
mapping. Manual and source-declared classifications are not overwritten.

FIRST EPSS and CISA KEV enrichment preserve UAE relevance fields, including
confidence. They do not calculate or clear UAE relevance confidence.

The read-only article and intelligence APIs expose confidence only through the
existing `uae_relevance_confidence` field. They return a JSON number for mapped
confidence and `null` when confidence is not assigned. No public mutation
endpoint or confidence filter is added by P4-02.

## Security Boundaries

P4-01/P4-02 do not add:

- network calls;
- machine learning or LLM classification;
- scheduler code;
- startup classification;
- background workers;
- public write APIs;
- ingestion endpoints;
- arbitrary URL input;
- dynamic untrusted regex;
- raw payload exposure;
- frontend UAE confidence filters.

## Limitations

P4-03 adds frontend geographic-scope and UAE relevance-status filters for the
dashboard article feed and vulnerability table. It does not add confidence
filters, ingestion triggers, scheduler code, or public mutation endpoints.

Scheduling remains deferred.

The confidence mapping is deterministic rule strength, not statistical
calibration. No statistical calibration dataset or machine-learning model is
used.

Rule-based matching can still produce false positives and false negatives.
