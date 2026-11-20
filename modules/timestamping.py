"""RFC 3161 trusted timestamps for the audit-chain head.

Anchoring sends **only the SHA-256 head hash** (no case data) to a Time-Stamp
Authority and stores the signed token. Later, anyone can show that the chain up
to that entry existed at the TSA's time — and the anchor also exposes any later
truncation or rewrite of the chain.

Disabled unless ``TRACE_TSA_URL`` is set (e.g. an approved government/CA TSA).
Optionally ``TRACE_TSA_CERT`` points to the TSA certificate (PEM) so the token
signature can be checked.
"""

from __future__ import annotations

import os
from typing import Any

from modules import database


def tsa_url() -> str:
    return os.environ.get("TRACE_TSA_URL", "").strip()


def _certificate() -> bytes | None:
    path = os.environ.get("TRACE_TSA_CERT", "").strip()
    if path and os.path.isfile(path):
        with open(path, "rb") as handle:
            return handle.read()
    return None


def anchor_audit_head() -> dict[str, Any]:
    import rfc3161ng

    url = tsa_url()
    if not url:
        raise RuntimeError("Set TRACE_TSA_URL to an approved RFC 3161 Time-Stamp Authority first.")
    head = database.audit_head()
    if head["seq"] == 0:
        raise RuntimeError("The audit log is empty.")
    digest = bytes.fromhex(head["hash"])
    stamper = rfc3161ng.RemoteTimestamper(url, certificate=_certificate(), hashname="sha256", timeout=20)
    token = stamper.timestamp(digest=digest)
    gen_time = rfc3161ng.get_timestamp(token, naive=False)
    database.save_audit_anchor(head["seq"], head["hash"], url, token, gen_time.isoformat())
    return {"seq": head["seq"], "hash": head["hash"], "tsa_time": gen_time.isoformat(), "tsa_url": url}


def verify_anchor_token(token: bytes, entry_hash: str) -> dict[str, Any]:
    """Check that a stored token commits to ``entry_hash`` (and its signature if a cert is set)."""
    import rfc3161ng

    result: dict[str, Any] = {"imprint_matches": False, "signature_checked": False}
    try:
        from pyasn1.codec.der import decoder
        decoded, _ = decoder.decode(token, asn1Spec=rfc3161ng.TimeStampToken())
        tst_info = decoded.tst_info
        imprint = bytes(tst_info["messageImprint"]["hashedMessage"])
        result["imprint_matches"] = imprint.hex() == entry_hash
        result["tsa_time"] = rfc3161ng.get_timestamp(token, naive=False).isoformat()
    except Exception as exc:
        result["error"] = str(exc)
        return result
    certificate = _certificate()
    if certificate:
        try:
            result["signature_valid"] = bool(rfc3161ng.check_timestamp(
                token, certificate=certificate, digest=bytes.fromhex(entry_hash), hashname="sha256"))
            result["signature_checked"] = True
        except Exception as exc:
            result["signature_valid"] = False
            result["signature_checked"] = True
            result["error"] = str(exc)
    return result
