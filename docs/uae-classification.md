# UAE Relevance Classification

## Purpose

P4-01 added deterministic offline classification for whether a normalized
public cybersecurity intelligence record contains direct UAE-related evidence.
P4-02 added a fixed deterministic confidence mapping for automatic rule results.
C08 B5-05 now separates authority-backed direct evidence from text-only
potential relevance and adds controlled evidence tags.

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

1. approved UAE authority source slug: direct UAE evidence;
2. country phrase, standalone UAE acronym, or emirate name: potential UAE
   relevance only;
3. existing structured UAE scope: potential UAE relevance;
4. explicit global scope without UAE evidence: global relevance;
5. otherwise: no demonstrated UAE relevance.

The strongest matching rule wins. Only an approved authority source sets
`uae_relevance_status=confirmed`. Text mentions set
`uae_relevance_status=possible`; they never assert attribution, targeting, or
authority publication. A structured UAE scope sets `probable`.

An explicit global record without UAE evidence is `not_relevant` for the UAE
view while remaining global intelligence. Other non-matches preserve scope and
use `unknown`, meaning no demonstrated UAE relevance.

## Rule-Strength Confidence

Automatic classifier confidence is stored in `uae_relevance_confidence` as a
nullable `numeric(4,3)` database value between `0.000` and `1.000`, and is
serialized by the read-only APIs as a JSON number or `null`.

The mapping is intentionally small and fixed:

| Rule ID | Confidence | Meaning |
|---|---:|---|
| `approved_uae_source` | `0.950` | Approved UAE cybersecurity or government source identity. |
| `structured_uae_scope` | `0.800` | Existing structured UAE geographic scope. |
| `text_country_mention` | `0.650` | Potential relevance from a country phrase. |
| `text_uae_acronym_mention` | `0.600` | Potential relevance from a standalone acronym. |
| `text_emirate_mention` | `0.550` | Potential relevance from an emirate name. |
| `explicit_global_scope` | `0.800` | Global intelligence with no demonstrated UAE evidence. |
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
- `uae-cyber-security-council-nibras`
- `desc-news`
- `desc-published-research`

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

## Controlled evidence tags

C08 persists deterministic tags through the existing tag tables; it adds no
schema or migration. System-controlled namespaces are `uae-authority-*`
(`general`), `uae-emirate-*` (`region`), `uae-sector-*` (`sector`), and
`language-*` (`theme`). Each API tag has a bounded label, confidence, and safe
evidence explanation. Apply runs reconcile only system assignments in those
namespaces and never delete or overwrite analyst-owned assignments. Sector and
language matches add descriptive metadata; they do not increase UAE relevance
or imply attribution.

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

C08 classification does not add:

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
