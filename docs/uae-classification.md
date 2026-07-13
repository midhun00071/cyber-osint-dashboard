# UAE Relevance Classification

## Purpose

P4-01 adds deterministic offline classification for whether a normalized public
cybersecurity intelligence record contains direct UAE-related evidence.

UAE relevance classification identifies whether a public cybersecurity
intelligence record contains direct UAE-related evidence. It does not establish
threat attribution, intent, targeting, or impact.

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
counts, and does not expose internal database IDs.

## Security Boundaries

P4-01 does not add:

- network calls;
- machine learning or LLM classification;
- scheduler code;
- startup classification;
- background workers;
- public write APIs;
- ingestion endpoints;
- arbitrary URL input;
- dynamic untrusted regex;
- raw payload exposure.

## Limitations

P4-02 confidence calibration remains incomplete. The classifier leaves
`uae_relevance_confidence` unset.

P4-03 frontend filters remain incomplete.

Scheduling remains deferred.

Rule-based matching can still produce false positives and false negatives.
