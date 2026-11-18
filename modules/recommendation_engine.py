"""Rule-based investigative leads with explicit source references."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any


def generate_investigative_leads(
    anomaly_records: list[dict[str, Any]],
    relationship_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    leads: list[dict[str, Any]] = []

    for record in anomaly_records:
        evidence_id = record.get("evidence_id", "Unknown evidence")
        row_number = record.get("row_number", "?")
        reasons = record.get("reasons", [])
        statement = (
            f"Review the activity recorded at row {row_number} of {record.get('filename', 'the source file')}. "
            "The automated screen found statistical or rule-based indicators that merit checking."
        )
        leads.append(_lead(
            "anomaly_review", statement,
            "Automated indicators: " + "; ".join(reasons),
            [evidence_id],
            "Compare the source row with surrounding records and verify account, device, timestamp, and timezone context.",
            f"{evidence_id}:{row_number}",
        ))

    by_identifier: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in relationship_records:
        for identifier in record.get("identities", []):
            by_identifier[identifier].append(record)

    for identifier, records in by_identifier.items():
        distinct_evidence = sorted({record["evidence_id"] for record in records})
        if len(distinct_evidence) < 2:
            continue
        file_names = sorted({record["filename"] for record in records})
        leads.append(_lead(
            "shared_identifier", 
            f"The identifier '{identifier}' appears in records from {len(distinct_evidence)} evidence files.",
            "This is an explicit string match. It may refer to the same account or entity, but identity has not been independently verified.",
            distinct_evidence,
            f"Confirm the identifier's meaning in {', '.join(file_names)} and check for aliases, shared accounts, or parsing errors.",
            identifier,
        ))

    return leads


def _lead(kind: str, statement: str, basis: str, evidence_ids: list[str],
          next_action: str, seed: str) -> dict[str, Any]:
    digest = hashlib.sha256(f"{kind}:{seed}".encode("utf-8")).hexdigest()[:10].upper()
    return {
        "lead_id": f"LEAD-{digest}",
        "type": kind,
        "statement": statement,
        "basis": basis,
        "supporting_evidence": evidence_ids,
        "suggested_follow_up": next_action,
        "status": "Unreviewed",
        "automated": True,
    }

