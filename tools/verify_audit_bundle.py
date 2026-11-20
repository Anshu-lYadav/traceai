#!/usr/bin/env python3
"""Independently verify a TRACE AI audit bundle (JSON export).

Needs only Python 3 and the `cryptography` package — not TRACE AI itself.

    python verify_audit_bundle.py bundle.json [--public-key trusted_key.pem]

Checks for every entry: the SHA-256 entry hash recomputed from its content, the
Ed25519 signature, and (for a full export) the link to the previous entry and the
sequence. Pass --public-key with a key obtained out-of-band (e.g. lodged with the
court) so a forged bundle signed with a different key is rejected.
"""

import argparse
import base64
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def entry_hash(entry):
    record = {
        "seq": entry["seq"], "case_id": entry["case_id"], "actor": entry["actor"],
        "event_type": entry["event_type"], "details": entry["details_json"],
        "created_at": entry["created_at"], "legacy": bool(entry["legacy"]),
        "prev_hash": entry["prev_hash"],
    }
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--public-key", help="Trusted PEM public key (recommended)")
    args = parser.parse_args()
    with open(args.bundle, encoding="utf-8") as handle:
        bundle = json.load(handle)
    pem = open(args.public_key).read() if args.public_key else bundle["public_key_pem"]
    if not args.public_key:
        print("WARNING: using the public key embedded in the bundle; supply --public-key "
              "from a trusted source for a meaningful check.")
    public = serialization.load_pem_public_key(pem.encode("ascii"))
    full_chain = not bundle.get("scope_case_id")
    problems, previous = [], "0" * 64
    for index, entry in enumerate(bundle["entries"]):
        if entry_hash(entry) != entry["entry_hash"]:
            problems.append(f"#{entry['seq']}: content does not match its hash")
        try:
            public.verify(base64.b64decode(entry["signature"]), entry["entry_hash"].encode("ascii"))
        except InvalidSignature:
            problems.append(f"#{entry['seq']}: invalid signature")
        if full_chain:
            if entry["seq"] != index + 1:
                problems.append(f"#{entry['seq']}: sequence gap (expected #{index + 1})")
            if entry["prev_hash"] != previous:
                problems.append(f"#{entry['seq']}: broken link to previous entry")
            previous = entry["entry_hash"]
    by_seq = {e["seq"]: e["entry_hash"] for e in bundle["entries"]}
    for anchor in bundle.get("anchors", []):
        if anchor["seq"] in by_seq and by_seq[anchor["seq"]] != anchor["entry_hash"]:
            problems.append(f"RFC 3161 anchor for #{anchor['seq']} does not match the chain")
    scope = "full chain" if full_chain else f"case {bundle['scope_case_id']} (per-entry signatures)"
    print(f"Checked {len(bundle['entries'])} entries — {scope}.")
    if problems:
        print("FAILED:")
        for problem in problems[:100]:
            print("  -", problem)
        sys.exit(1)
    print("OK: every entry is intact and signed by the given key.")


if __name__ == "__main__":
    main()
