# C10 outbound and third-party consumption matrix

Static review covered all 11 production `httpx` client implementations and their source-policy/adaptor boundaries. Tests use mocked transports only; no live OSINT request was sent. Every owned client uses bounded HTTPX timeouts, `follow_redirects=False`, and `trust_env=False`. Fixed feed clients without an explicitly registered alternate endpoint reject every redirect without inspecting `Location`; clients which permit a small redirect count revalidate every target against their immutable HTTPS policy.

| Client / source | Immutable destination | Redirect policy | Authentication / proxy | Request, size, and representation bounds | Status and evidence |
|---|---|---|---|---|---|
| NVD CVE API | `services.nvd.nist.gov/rest/json/cves/2.0` | Reject | Optional API key header; `trust_env=False` | connect/read/write/pool timeout; page size <=2,000; date window <=120 days; 20 MiB decompressed body; JSON media type when declared; bounded paging | SAFE after C10-F-003/F-004; `nvd_client.py`, NVD and C10 outbound tests |
| FIRST EPSS | `api.first.org/data/v1/epss` | Reject | None; `trust_env=False` | CVE query <=2,000 chars; batch <=100; handler total <=500; 2 MiB decompressed body; JSON media type when declared | SAFE after C10-F-003/F-004; `epss_client.py`, EPSS and C10 outbound tests |
| CISA KEV | exact registry URL under `www.cisa.gov` | **REJECT**; no `Location` inspection or second request | None; `trust_env=False` | bounded timeout; 2 MiB decompressed JSON; exact starting endpoint; sanitized failures | SAFE after C10-F-003/F-008; fixed endpoint and all 301/302/303/307/308 responses tested |
| CERT-EU RSS | exact registry feed under `cert.europa.eu` | **REJECT**; no `Location` inspection or second request | None; `trust_env=False` | bounded timeout; 1 MiB decompressed XML; bounded feed parse | SAFE after C10-F-003/F-008; source remains governed by registry/default handler state |
| Google Threat Intelligence RSS | exact registry feed under `feeds.feedburner.com` | **REJECT**; no `Location` inspection or second request | None; `trust_env=False` | bounded timeout; 2 MiB decompressed XML; <=100 entries and bounded text | SAFE after C10-F-003/F-008; no default scheduling activation |
| Official RSS (CERT-FR alerts/advisories and UK NCSC reports) | fixed per-source HTTPS host and path policy | **REJECT** | None; `trust_env=False` | 1 MiB body; bounded XML nodes/depth/entries; safe defused XML parsing | SAFE/DISABLED; all three remain unscheduled as required |
| Anomali publications | `www.anomali.com/blog` and same-policy article paths | Up to 3, each target revalidated | None; `trust_env=False` | overall and per-request time budgets; 2 MiB body; <=20 records; bounded HTML/JSON-LD nodes, depth, strings | SAFE; mocked collector suite |
| Censys publications | fixed `censys.com/censys-arc/...` discovery and article paths | Up to 3, each target revalidated | None; `trust_env=False` | bounded timeout; 2 MiB body; record and HTML/JSON-LD bounds | SAFE; mocked collector suite |
| DESC publications | two exact `www.desc.gov.ae` pages | Reject | None; `trust_env=False` | bounded timeout; 2 MiB body; <=50 records; <=25,000 DOM nodes; bounded text | SAFE/APPROVAL-GATED; automated UAE access remains disabled |
| MITRE ATT&CK TAXII | fixed `attack-taxii.mitre.org` HTTPS API root/collections | Reject | None; `trust_env=False` | bounded timeout, page/object/byte/depth limits; pagination URL revalidation; JSON validation | SAFE/DISABLED; `mitre-attack-enterprise` remains unscheduled |
| Internal system-health probe | fixed Compose backend/Prefect health URI derived from trusted configuration | Reject | None; `trust_env=False` | short timeout; 4,096-byte streamed response; JSON/sanitized state | SAFE; private infrastructure check, not arbitrary user input |

## Non-network adapters

Anomali, Censys, IBM X-Force, official RSS, Google, STIX, and related publication adapters also validate stored/publication URLs. They do not initiate HTTP requests. File-backed import adapters enforce regular-file, path, byte, object, string, depth, and record limits and reject remote-looking paths.

## Cross-client controls

- The source registry owns approved base URLs/hosts; runtime requests cannot supply an alternate API root, host, port, header set, cookie, or callback URL.
- Fixed-feed redirect responses fail closed before `Location` is read. Only clients with an explicit registered redirect policy parse and revalidate a target before another request; pagination links remain revalidated.
- Response bodies are counted while streamed, so decompression does not bypass byte ceilings. Explicitly wrong media types are rejected where structured JSON/XML/HTML is required.
- Errors and logs expose stable categories, not URLs containing credentials, response bodies, headers, or transport exceptions.
- `DEFAULT_SOURCE_HANDLERS_COUNT = 0` remains preserved. No source was enabled or scheduled by C10.

Reviewer/sign-off: **Pending independent review**.
