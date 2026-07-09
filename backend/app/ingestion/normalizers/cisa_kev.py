"""Pure normalization for public CISA KEV catalog entries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
import re
from typing import Any


MAX_PAYLOAD_BYTES = 16 * 1024
MAX_VENDOR_PROJECT_LENGTH = 300
MAX_PRODUCT_LENGTH = 300
MAX_VULNERABILITY_NAME_LENGTH = 500
MAX_SHORT_DESCRIPTION_LENGTH = 10_000
MAX_REQUIRED_ACTION_LENGTH = 2_000
MAX_NOTES_LENGTH = 2_000
CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE | re.ASCII)
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", re.ASCII)


class CisaKevNormalizationError(ValueError):
    """A CISA KEV entry could not be safely normalized."""


class CisaKevPayloadTooLargeError(CisaKevNormalizationError):
    """A CISA KEV entry exceeded the approved source-payload size limit."""


@dataclass(frozen=True)
class NormalizedCisaKevEntry:
    """Validated database-ready values derived from one CISA KEV entry."""

    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: date
    short_description: str | None
    required_action: str | None
    due_date: date
    known_ransomware_campaign_use: bool
    notes: str | None
    raw_payload: dict[str, Any]
    content_hash: str


def extract_cisa_kev_entries(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Return raw KEV entries from a parsed catalog object."""

    if not isinstance(catalog, dict):
        raise CisaKevNormalizationError("The CISA KEV catalog must be an object.")
    entries = catalog.get("vulnerabilities")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise CisaKevNormalizationError(
            "The CISA KEV vulnerabilities field must be a list of objects."
        )
    return list(entries)


def normalize_cisa_kev_entry(entry: dict[str, Any]) -> NormalizedCisaKevEntry:
    """Normalize one CISA KEV entry without network or database side effects."""

    if not isinstance(entry, dict):
        raise CisaKevNormalizationError("The CISA KEV entry must be an object.")

    cve_id = _normalize_cve_id(entry.get("cveID"))
    vendor_project = _optional_text(entry.get("vendorProject"), MAX_VENDOR_PROJECT_LENGTH)
    product = _optional_text(entry.get("product"), MAX_PRODUCT_LENGTH)
    vulnerability_name = _optional_text(
        entry.get("vulnerabilityName"),
        MAX_VULNERABILITY_NAME_LENGTH,
    )
    date_added = _strict_date(entry.get("dateAdded"), "date added")
    short_description = _optional_text(
        entry.get("shortDescription"),
        MAX_SHORT_DESCRIPTION_LENGTH,
    )
    required_action = _optional_text(
        entry.get("requiredAction"),
        MAX_REQUIRED_ACTION_LENGTH,
    )
    due_date = _strict_date(entry.get("dueDate"), "due date")
    ransomware = _ransomware_use(entry.get("knownRansomwareCampaignUse"))
    notes = _optional_text(entry.get("notes"), MAX_NOTES_LENGTH)

    raw_payload = {
        "cveID": cve_id,
        "vendorProject": vendor_project,
        "product": product,
        "vulnerabilityName": vulnerability_name,
        "dateAdded": date_added.isoformat(),
        "shortDescription": short_description,
        "requiredAction": required_action,
        "dueDate": due_date.isoformat(),
        "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
        "notes": notes,
    }
    canonical_bytes = _canonical_bytes(raw_payload)
    return NormalizedCisaKevEntry(
        cve_id=cve_id,
        vendor_project=vendor_project,
        product=product,
        vulnerability_name=vulnerability_name,
        date_added=date_added,
        short_description=short_description,
        required_action=required_action,
        due_date=due_date,
        known_ransomware_campaign_use=ransomware,
        notes=notes,
        raw_payload=json.loads(canonical_bytes),
        content_hash=sha256(canonical_bytes).hexdigest(),
    )


def deduplicate_cisa_kev_entries(
    records: list[NormalizedCisaKevEntry],
) -> list[NormalizedCisaKevEntry]:
    """Collapse exact duplicate CVEs and reject conflicting KEV duplicates."""

    by_cve: dict[str, NormalizedCisaKevEntry] = {}
    ordered: list[NormalizedCisaKevEntry] = []
    for record in records:
        existing = by_cve.get(record.cve_id)
        if existing is None:
            by_cve[record.cve_id] = record
            ordered.append(record)
            continue
        if existing.content_hash != record.content_hash:
            raise CisaKevNormalizationError(
                "Conflicting duplicate CISA KEV entries were returned."
            )
    return ordered


def _normalize_cve_id(value: object) -> str:
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        raise CisaKevNormalizationError(
            "The CISA KEV entry contains an invalid CVE ID."
        )
    return value.upper()


def _strict_date(value: object, field_name: str) -> date:
    if not isinstance(value, str) or DATE_PATTERN.fullmatch(value) is None:
        raise CisaKevNormalizationError(f"The CISA KEV {field_name} is invalid.")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise CisaKevNormalizationError(
            f"The CISA KEV {field_name} is invalid."
        ) from exc


def _ransomware_use(value: object) -> bool:
    if not isinstance(value, str):
        raise CisaKevNormalizationError(
            "The CISA KEV ransomware campaign field is invalid."
        )
    normalized = value.strip().casefold()
    if normalized == "known":
        return True
    if normalized == "unknown":
        return False
    raise CisaKevNormalizationError(
        "The CISA KEV ransomware campaign field is invalid."
    )


def _optional_text(value: object, maximum_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CisaKevNormalizationError("A CISA KEV text field is invalid.")
    text = re.sub(r"\s+", " ", value).strip()
    return text[:maximum_length] or None


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    try:
        canonical_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CisaKevNormalizationError(
            "The CISA KEV entry is not valid canonical JSON."
        ) from exc

    canonical_bytes = canonical_json.encode("utf-8")
    if len(canonical_bytes) > MAX_PAYLOAD_BYTES:
        raise CisaKevPayloadTooLargeError(
            "The CISA KEV entry exceeds the 16 KiB payload limit."
        )
    return canonical_bytes
