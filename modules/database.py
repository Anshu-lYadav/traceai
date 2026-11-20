"""Encrypted local persistence for cases, evidence, custody, audit, and reports.

Security model
--------------
* The SQLite database is encrypted with SQLCipher (AES-256) when the
  ``sqlcipher3`` package is installed; otherwise the app runs unencrypted and
  says so (``DB_ENCRYPTED``).  An existing plaintext database is migrated in
  place on first start and the plaintext copy is moved to
  ``data/pre_encryption_backup/`` for the operator to destroy.
* Evidence originals are stored as authenticated AES-256-GCM ``.enc`` files.
* Every audit event is appended to ``audit_log``: a single hash chain where each
  entry commits to the previous one and is signed with an Ed25519 key kept
  outside ``data/``.  SQL triggers block UPDATE/DELETE; ``verify_audit_chain``
  detects any edit made by bypassing them.  ``audit_anchors`` can hold RFC 3161
  timestamp tokens for the chain head, which also detect truncation.
* Chain-of-custody records (provenance, custody transfers) are append-only.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import math
import os
import re
import shutil
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from modules import crypto
from modules.chunking import make_chunks

try:  # SQLCipher build of SQLite (encrypted database)
    from sqlcipher3 import dbapi2 as sqlite3
    DB_ENCRYPTED = True
except ImportError:  # pragma: no cover - depends on platform wheels
    import sqlite3  # type: ignore[no-redef]
    DB_ENCRYPTED = False


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DATABASE_PATH = DATA_DIR / "trace_ai.db"

GENESIS_HASH = "0" * 64
_SQLITE_PLAIN_HEADER = b"SQLite format 3\x00"
_actor: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_actor", default=None)


# --------------------------------------------------------------------------- #
# Connection, actor, helpers
# --------------------------------------------------------------------------- #
def set_actor(email: str | None) -> None:
    """Identify who performs the following database actions (for the audit chain)."""
    _actor.set(email)


@contextmanager
def acting_as(email: str | None) -> Iterator[None]:
    token = _actor.set(email)
    try:
        yield
    finally:
        _actor.reset(token)


def current_actor() -> str:
    return _actor.get() or "system"


def _apply_key(connection) -> None:
    if DB_ENCRYPTED:
        connection.execute(f"PRAGMA key = \"x'{crypto.database_key_hex()}'\"")


def _is_plaintext_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(16) == _SQLITE_PLAIN_HEADER
    except OSError:
        return False


def _migrate_plaintext_database() -> None:
    """Convert an unencrypted database to SQLCipher, keeping a plaintext backup."""
    if not DB_ENCRYPTED or not DATABASE_PATH.exists() or not _is_plaintext_sqlite(DATABASE_PATH):
        return
    encrypted_path = DATABASE_PATH.with_suffix(".encrypting")
    encrypted_path.unlink(missing_ok=True)
    plain = sqlite3.connect(str(DATABASE_PATH))
    try:
        tables = [row[0] for row in plain.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )]
        counts = {t: plain.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
        plain.execute(
            f"ATTACH DATABASE ? AS encrypted KEY \"x'{crypto.database_key_hex()}'\"",
            (str(encrypted_path),),
        )
        plain.execute("SELECT sqlcipher_export('encrypted')")
        plain.execute("DETACH DATABASE encrypted")
    finally:
        plain.close()
    check = sqlite3.connect(str(encrypted_path))
    try:
        _apply_key(check)
        for table, expected in counts.items():
            actual = check.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            if actual != expected:
                raise RuntimeError(f"Encryption migration check failed for table {table}.")
    finally:
        check.close()
    backup_dir = DATA_DIR / "pre_encryption_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(DATABASE_PATH), backup_dir / DATABASE_PATH.name)
    os.replace(encrypted_path, DATABASE_PATH)


@contextmanager
def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DATABASE_PATH), timeout=30)
    _apply_key(connection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_relative_path(value: str) -> str:
    return str(value).replace("\\", "/")


def _resolve_original_path(value: str) -> Path:
    candidate = Path(_normalize_relative_path(value))
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def _relative(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _originals_to_remove(connection, relative_paths: list[str]) -> list[Path]:
    targets: list[Path] = []
    seen: set[Path] = set()
    remaining = [
        _resolve_original_path(row["original_path"])
        for row in connection.execute("SELECT original_path FROM evidence").fetchall()
    ]
    for relative in relative_paths:
        target = _resolve_original_path(relative)
        try:
            target.relative_to(EVIDENCE_DIR.resolve())
        except ValueError:
            continue
        if target in seen or target in remaining:
            continue
        seen.add(target)
        targets.append(target)
    return targets


def _unlink_files(paths: list[Path]) -> tuple[int, list[str]]:
    removed = 0
    warnings: list[str] = []
    for path in paths:
        try:
            if path.is_file():
                path.unlink()
                removed += 1
        except OSError as exc:
            warnings.append(f"{path.name}: {exc}")
    return removed, warnings


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item"):
        try:
            return _json_safe(value.item())
        except (ValueError, TypeError):
            pass
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (ValueError, TypeError):
            pass
    return str(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, allow_nan=False)


def _canonical(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    raw_bytes INTEGER NOT NULL,
    extracted_text TEXT NOT NULL DEFAULT '',
    extraction_status TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    original_path TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    UNIQUE(case_id, sha256)
);

CREATE TABLE IF NOT EXISTS chat_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    sources_json TEXT NOT NULL DEFAULT '[]',
    retrieval_query TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Legacy mutable log. Rows are copied into audit_log once; no new writes.
CREATE TABLE IF NOT EXISTS activity_log (
    activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    event_type TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigative_leads (
    lead_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    type TEXT NOT NULL,
    content_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Unreviewed',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_results (
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    analysis_type TEXT NOT NULL,
    result_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(case_id, analysis_type)
);

CREATE TABLE IF NOT EXISTS evidence_chunks (
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    chunk_id INTEGER NOT NULL,
    chunk_text TEXT NOT NULL,
    model_name TEXT NOT NULL,
    dimension INTEGER NOT NULL,
    embedding BLOB NOT NULL,
    indexed_at TEXT NOT NULL,
    PRIMARY KEY(case_id,evidence_id,chunk_id,model_name)
);

-- Signed, hash-chained, append-only audit trail (all cases + system events).
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    case_id TEXT,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    legacy INTEGER NOT NULL DEFAULT 0,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_head (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    seq INTEGER NOT NULL,
    last_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_anchors (
    anchor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    tsa_url TEXT NOT NULL,
    token BLOB NOT NULL,
    gen_time TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_members (
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    user_id TEXT NOT NULL,
    case_role TEXT NOT NULL CHECK(case_role IN ('lead', 'investigator', 'viewer')),
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY(case_id, user_id)
);

-- Write-once acquisition record per evidence item (no FK: survives deletion).
CREATE TABLE IF NOT EXISTS evidence_provenance (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    source_description TEXT NOT NULL,
    device_identifier TEXT NOT NULL DEFAULT '',
    acquired_by TEXT NOT NULL,
    acquisition_method TEXT NOT NULL,
    acquisition_tool TEXT NOT NULL DEFAULT '',
    acquired_at TEXT NOT NULL,
    legal_authority TEXT NOT NULL,
    certificate_reference TEXT NOT NULL DEFAULT '',
    acquisition_sha256 TEXT NOT NULL DEFAULT '',
    hash_verified INTEGER,
    notes TEXT NOT NULL DEFAULT '',
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_party TEXT NOT NULL DEFAULT '',
    to_party TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'English',
    content TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    verification_json TEXT NOT NULL DEFAULT '{}',
    sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    evidence_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    summary TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    fields_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS evidence_passages (
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    evidence_id TEXT NOT NULL,
    chunk_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY(case_id, evidence_id, chunk_id)
);

CREATE TABLE IF NOT EXISTS evidence_translations (
    evidence_id TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    language TEXT NOT NULL,
    text TEXT NOT NULL,
    model TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(evidence_id, language)
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    progress REAL NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_chat_case ON chat_messages(case_id, message_id);
CREATE INDEX IF NOT EXISTS idx_activity_case ON activity_log(case_id, activity_id);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id, seq);
CREATE INDEX IF NOT EXISTS idx_members_user ON case_members(user_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id, event_id);
CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_timeline_case_ts ON timeline_events(case_id, ts);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);

CREATE VIRTUAL TABLE IF NOT EXISTS passages_fts USING fts5(
    text, case_id UNINDEXED, evidence_id UNINDEXED, chunk_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 0'
);
"""

_APPEND_ONLY_TABLES = ("audit_log", "audit_anchors", "custody_events", "evidence_provenance")


def _append_only_triggers(connection) -> None:
    for table in _APPEND_ONLY_TABLES:
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                f"SELECT RAISE(ABORT, '{table} is append-only'); END"
            )


def _add_column(connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def initialize_database() -> None:
    """Create or upgrade the local schema. Safe to call at app startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _migrate_plaintext_database()
    with _connect() as connection:
        connection.executescript(_SCHEMA)
        _add_column(connection, "chat_messages", "retrieval_query", "TEXT NOT NULL DEFAULT ''")
        _add_column(connection, "chat_messages", "meta_json", "TEXT NOT NULL DEFAULT '{}'")
        _add_column(connection, "evidence", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")
        _add_column(connection, "cases", "created_by", "TEXT NOT NULL DEFAULT ''")
        _add_column(connection, "cases", "deleted_at", "TEXT")
        _add_column(connection, "cases", "deleted_by", "TEXT")
        connection.execute(
            "UPDATE evidence SET original_path = REPLACE(original_path, '\\', '/') "
            "WHERE original_path LIKE '%\\%'"
        )
        if connection.execute("SELECT 1 FROM audit_head WHERE id=1").fetchone() is None:
            connection.execute("INSERT INTO audit_head(id,seq,last_hash) VALUES(1,0,?)", (GENESIS_HASH,))
        _import_legacy_logs(connection)
        _append_only_triggers(connection)
        # Jobs that were running when the server stopped go back in the queue.
        connection.execute(
            "UPDATE jobs SET status='queued',message='Re-queued after restart' WHERE status='running'"
        )
    _encrypt_legacy_originals()
    _backfill_passages()


def _import_legacy_logs(connection) -> None:
    """Copy the old mutable activity/auth logs into the signed chain once."""
    if connection.execute("SELECT 1 FROM audit_log LIMIT 1").fetchone():
        return
    rows = []
    for row in connection.execute(
        "SELECT case_id,event_type,details_json,created_at FROM activity_log ORDER BY activity_id"
    ).fetchall():
        details = json.loads(row["details_json"] or "{}")
        rows.append((row["created_at"], row["case_id"], details.get("officer") or "unknown",
                     row["event_type"], details))
    has_auth = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_log'"
    ).fetchone()
    if has_auth:
        for row in connection.execute(
            "SELECT email,event_type,actor_email,created_at FROM auth_log ORDER BY log_id"
        ).fetchall():
            rows.append((row["created_at"], None, row["actor_email"] or row["email"],
                         f"auth.{row['event_type']}", {"email": row["email"]}))
    if not rows:
        return
    rows.sort(key=lambda item: item[0])
    for created_at, case_id, actor, event_type, details in rows:
        _append_audit(connection, case_id, event_type, details, actor=actor,
                      created_at=created_at, legacy=True)
    _append_audit(connection, None, "audit_chain_initialized", {
        "legacy_entries_imported": len(rows),
        "note": "Legacy entries were unsigned before import; their content is protected "
                "only from the import time onward.",
    }, actor="system")


def _encrypt_legacy_originals() -> None:
    """Encrypt any plaintext evidence originals left by earlier versions."""
    with _connect() as connection:
        rows = connection.execute(
            "SELECT evidence_id,sha256,original_path FROM evidence"
        ).fetchall()
    backup_dir = DATA_DIR / "pre_encryption_backup" / "evidence"
    for row in rows:
        path = _resolve_original_path(row["original_path"])
        if not path.is_file() or crypto.is_encrypted_file(path):
            continue
        target = EVIDENCE_DIR / f"{row['evidence_id']}.enc"
        with open(path, "rb") as source:
            digest, _ = crypto.encrypt_stream(source, target)
        if crypto.plaintext_sha256(target) != digest:
            target.unlink(missing_ok=True)
            continue
        with _connect() as connection:
            connection.execute(
                "UPDATE evidence SET original_path=? WHERE evidence_id=?",
                (_relative(target), row["evidence_id"]),
            )
            still_used = connection.execute(
                "SELECT 1 FROM evidence WHERE original_path=?", (row["original_path"],)
            ).fetchone()
        if not still_used:
            backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), backup_dir / path.name)


def _backfill_passages() -> None:
    with _connect() as connection:
        missing = connection.execute(
            """SELECT e.case_id,e.evidence_id,e.extracted_text FROM evidence e
               WHERE e.extracted_text != '' AND NOT EXISTS (
                   SELECT 1 FROM evidence_passages p WHERE p.evidence_id=e.evidence_id)"""
        ).fetchall()
        for row in missing:
            _write_passages(connection, row["case_id"], row["evidence_id"], row["extracted_text"])


# --------------------------------------------------------------------------- #
# Audit chain
# --------------------------------------------------------------------------- #
def _entry_hash(seq: int, case_id: str | None, actor: str, event_type: str,
                details_json: str, created_at: str, legacy: bool, prev_hash: str) -> str:
    record = {
        "seq": seq, "case_id": case_id, "actor": actor, "event_type": event_type,
        "details": details_json, "created_at": created_at, "legacy": bool(legacy),
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


def _append_audit(connection, case_id: str | None, event_type: str,
                  details: dict[str, Any] | None = None, *, actor: str | None = None,
                  created_at: str | None = None, legacy: bool = False) -> int:
    # Writing to audit_head first takes SQLite's write lock, so concurrent
    # writers cannot both extend the chain from the same head.
    connection.execute("UPDATE audit_head SET seq=seq WHERE id=1")
    head = connection.execute("SELECT seq,last_hash FROM audit_head WHERE id=1").fetchone()
    seq = head["seq"] + 1
    actor = actor or current_actor()
    created_at = created_at or _now()
    details_json = _canonical(details or {})
    entry_hash = _entry_hash(seq, case_id, actor, event_type, details_json, created_at,
                             legacy, head["last_hash"])
    connection.execute(
        """INSERT INTO audit_log(seq,case_id,actor,event_type,details_json,created_at,legacy,
                                 prev_hash,entry_hash,signature,key_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (seq, case_id, actor, event_type, details_json, created_at, int(legacy),
         head["last_hash"], entry_hash, crypto.sign(entry_hash.encode("ascii")),
         crypto.public_key_id()),
    )
    connection.execute("UPDATE audit_head SET seq=?,last_hash=? WHERE id=1", (seq, entry_hash))
    return seq


def _log(connection, case_id: str | None, event_type: str,
         details: dict[str, Any] | None = None) -> None:
    _append_audit(connection, case_id, event_type, details)


def append_system_audit(event_type: str, details: dict[str, Any] | None = None,
                        actor: str | None = None, connection=None) -> None:
    if connection is not None:
        _append_audit(connection, None, event_type, details, actor=actor)
        return
    with _connect() as own:
        _append_audit(own, None, event_type, details, actor=actor)


def log_activity(case_id: str, event_type: str, details: dict[str, Any]) -> None:
    with _connect() as connection:
        _log(connection, case_id, event_type, details)


def list_activity(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT seq,actor,event_type,details_json,created_at,entry_hash FROM audit_log "
            "WHERE case_id=? ORDER BY seq",
            (case_id,),
        ).fetchall()
    return [
        {"seq": row["seq"], "actor": row["actor"], "event_type": row["event_type"],
         "details": json.loads(row["details_json"]), "created_at": row["created_at"],
         "entry_hash": row["entry_hash"]}
        for row in rows
    ]


def list_system_audit(prefix: str = "", limit: int = 200) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT seq,actor,event_type,details_json,created_at FROM audit_log "
            "WHERE case_id IS NULL AND event_type LIKE ? ORDER BY seq DESC LIMIT ?",
            (prefix + "%", limit),
        ).fetchall()
    return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]


def verify_audit_chain() -> dict[str, Any]:
    """Recompute every hash and signature. Detects edits, inserts, and reordering.

    Truncation of the newest entries is detected only by comparing the head with
    an external anchor (RFC 3161 token or an exported head hash).
    """
    problems: list[str] = []
    previous = GENESIS_HASH
    expected_seq = 1
    count = 0
    with _connect() as connection:
        head = connection.execute("SELECT seq,last_hash FROM audit_head WHERE id=1").fetchone()
        rows = connection.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        anchors = connection.execute(
            "SELECT seq,entry_hash,tsa_url,gen_time FROM audit_anchors ORDER BY anchor_id"
        ).fetchall()
    by_seq = {}
    for row in rows:
        count += 1
        if row["seq"] != expected_seq:
            problems.append(f"Sequence gap: expected #{expected_seq}, found #{row['seq']}.")
            expected_seq = row["seq"]
        if row["prev_hash"] != previous:
            problems.append(f"Entry #{row['seq']} does not link to the previous entry.")
        recomputed = _entry_hash(row["seq"], row["case_id"], row["actor"], row["event_type"],
                                 row["details_json"], row["created_at"], bool(row["legacy"]),
                                 row["prev_hash"])
        if recomputed != row["entry_hash"]:
            problems.append(f"Entry #{row['seq']} content was modified after it was written.")
        if not crypto.verify_signature(row["entry_hash"].encode("ascii"), row["signature"]):
            problems.append(f"Entry #{row['seq']} signature is invalid.")
        by_seq[row["seq"]] = row["entry_hash"]
        previous = row["entry_hash"]
        expected_seq += 1
    if head and (head["seq"] != count or head["last_hash"] != previous):
        problems.append("Chain head does not match the last entry (entries removed or added).")
    for anchor in anchors:
        if by_seq.get(anchor["seq"]) != anchor["entry_hash"]:
            problems.append(
                f"Trusted timestamp anchor for entry #{anchor['seq']} no longer matches the chain."
            )
    return {
        "valid": not problems,
        "entries": count,
        "head_seq": head["seq"] if head else 0,
        "head_hash": previous,
        "anchors": len(anchors),
        "last_anchor": dict(anchors[-1]) if anchors else None,
        "problems": problems[:50],
        "public_key_id": crypto.public_key_id(),
    }


def audit_head() -> dict[str, Any]:
    with _connect() as connection:
        row = connection.execute("SELECT seq,last_hash FROM audit_head WHERE id=1").fetchone()
    return {"seq": row["seq"], "hash": row["last_hash"]}


def save_audit_anchor(seq: int, entry_hash: str, tsa_url: str, token: bytes,
                      gen_time: str | None) -> None:
    with _connect() as connection:
        connection.execute(
            "INSERT INTO audit_anchors(seq,entry_hash,tsa_url,token,gen_time,created_at,created_by) "
            "VALUES(?,?,?,?,?,?,?)",
            (seq, entry_hash, tsa_url, token, gen_time, _now(), current_actor()),
        )
        _append_audit(connection, None, "audit_chain_anchored", {
            "anchored_seq": seq, "anchored_hash": entry_hash, "tsa_url": tsa_url,
            "tsa_time": gen_time,
        })


def export_audit_bundle(case_id: str | None = None) -> dict[str, Any]:
    """Everything a third party needs to verify the chain independently."""
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        anchors = connection.execute("SELECT * FROM audit_anchors ORDER BY anchor_id").fetchall()
    import base64
    entries = [{k: row[k] for k in row.keys()} for row in rows]
    chain = verify_audit_chain()
    if case_id:
        # Case-scoped export: only this case's entries (other cases stay confidential).
        # Each entry's signature can be verified on its own; completeness of the whole
        # chain is attested by the verification result below, made at export time.
        entries = [entry for entry in entries if entry["case_id"] == case_id]
    return {
        "chain_verification_at_export": {k: chain[k] for k in ("valid", "entries", "head_seq",
                                                               "head_hash", "anchors", "problems")},
        "format": "trace-ai-audit-bundle/1",
        "exported_at": _now(),
        "exported_by": current_actor(),
        "scope_case_id": case_id,
        "hash_algorithm": "sha256 over canonical JSON {seq,case_id,actor,event_type,details,"
                          "created_at,legacy,prev_hash} (sorted keys, no spaces, UTF-8)",
        "signature_algorithm": "Ed25519 over the ASCII hex entry_hash",
        "public_key_pem": crypto.public_key_pem(),
        "public_key_id": crypto.public_key_id(),
        "entries": entries,
        "anchors": [
            {**{k: a[k] for k in a.keys() if k != "token"},
             "token_base64": base64.b64encode(a["token"]).decode("ascii")}
            for a in anchors
        ],
    }


# --------------------------------------------------------------------------- #
# Cases and membership
# --------------------------------------------------------------------------- #
CASE_ROLES = ("lead", "investigator", "viewer")


def create_case(case_id: str, name: str, description: str = "",
                created_by_user_id: str | None = None) -> None:
    case_id = case_id.strip()
    name = name.strip()
    if not case_id or not name:
        raise ValueError("Case ID and case name are required.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id):
        raise ValueError("Case ID may use letters, numbers, '.', '_' and '-' (max 64).")
    timestamp = _now()
    with _connect() as connection:
        if connection.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
            raise ValueError("This case ID already exists (or belonged to a deleted case).")
        connection.execute(
            "INSERT INTO cases(case_id,name,description,created_at,updated_at,created_by) "
            "VALUES(?,?,?,?,?,?)",
            (case_id, name, description.strip(), timestamp, timestamp, current_actor()),
        )
        if created_by_user_id:
            connection.execute(
                "INSERT INTO case_members(case_id,user_id,case_role,added_by,added_at) VALUES(?,?,?,?,?)",
                (case_id, created_by_user_id, "lead", current_actor(), timestamp),
            )
        _log(connection, case_id, "case_created", {"name": name})


def ensure_default_case() -> None:
    with _connect() as connection:
        exists = connection.execute("SELECT 1 FROM cases WHERE deleted_at IS NULL LIMIT 1").fetchone()
        if not exists and not connection.execute("SELECT 1 FROM cases WHERE case_id='CASE-001'").fetchone():
            timestamp = _now()
            connection.execute(
                "INSERT INTO cases(case_id,name,description,created_at,updated_at,created_by) "
                "VALUES(?,?,?,?,?,?)",
                ("CASE-001", "Default Investigation", "", timestamp, timestamp, "system"),
            )
            _log(connection, "CASE-001", "case_created", {"name": "Default Investigation"})


def list_cases(user_id: str | None = None, include_all: bool = True) -> list[dict[str, Any]]:
    """Active cases. With ``include_all=False`` only cases ``user_id`` is a member of."""
    query = ("SELECT c.case_id,c.name,c.description,c.created_at,c.updated_at,c.created_by "
             "FROM cases c WHERE c.deleted_at IS NULL")
    params: tuple = ()
    if not include_all:
        query += " AND EXISTS (SELECT 1 FROM case_members m WHERE m.case_id=c.case_id AND m.user_id=?)"
        params = (user_id,)
    with _connect() as connection:
        rows = connection.execute(query + " ORDER BY c.created_at,c.case_id", params).fetchall()
    return [dict(row) for row in rows]


def get_case_role(case_id: str, user_id: str) -> str | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT case_role FROM case_members WHERE case_id=? AND user_id=?", (case_id, user_id)
        ).fetchone()
    return row["case_role"] if row else None


def list_case_members(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT user_id,case_role,added_by,added_at FROM case_members WHERE case_id=? ORDER BY added_at",
            (case_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def set_case_member(case_id: str, user_id: str, case_role: str, user_email: str = "") -> None:
    if case_role not in CASE_ROLES:
        raise ValueError("Unknown case role.")
    with _connect() as connection:
        connection.execute(
            """INSERT INTO case_members(case_id,user_id,case_role,added_by,added_at) VALUES(?,?,?,?,?)
               ON CONFLICT(case_id,user_id) DO UPDATE SET case_role=excluded.case_role""",
            (case_id, user_id, case_role, current_actor(), _now()),
        )
        _log(connection, case_id, "case_member_set", {"member": user_email or user_id, "case_role": case_role})


def remove_case_member(case_id: str, user_id: str, user_email: str = "") -> None:
    with _connect() as connection:
        leads = connection.execute(
            "SELECT user_id FROM case_members WHERE case_id=? AND case_role='lead'", (case_id,)
        ).fetchall()
        if [row["user_id"] for row in leads] == [user_id]:
            raise ValueError("A case must keep at least one lead investigator.")
        connection.execute("DELETE FROM case_members WHERE case_id=? AND user_id=?", (case_id, user_id))
        _log(connection, case_id, "case_member_removed", {"member": user_email or user_id})


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
PROVENANCE_REQUIRED = ("source_description", "acquired_by", "acquisition_method",
                       "acquired_at", "legal_authority")


def _write_passages(connection, case_id: str, evidence_id: str, text: str) -> int:
    connection.execute("DELETE FROM evidence_passages WHERE case_id=? AND evidence_id=?", (case_id, evidence_id))
    connection.execute("DELETE FROM passages_fts WHERE case_id=? AND evidence_id=?", (case_id, evidence_id))
    chunks = make_chunks(text)
    connection.executemany(
        "INSERT INTO evidence_passages(case_id,evidence_id,chunk_id,text) VALUES(?,?,?,?)",
        [(case_id, evidence_id, c["chunk_id"], c["text"]) for c in chunks],
    )
    connection.executemany(
        "INSERT INTO passages_fts(text,case_id,evidence_id,chunk_id) VALUES(?,?,?,?)",
        [(c["text"], case_id, evidence_id, c["chunk_id"]) for c in chunks],
    )
    return len(chunks)


def _validate_provenance(provenance: dict[str, Any], digest: str) -> dict[str, Any]:
    clean = {key: str(value or "").strip() for key, value in provenance.items()}
    missing = [field for field in PROVENANCE_REQUIRED if not clean.get(field)]
    if missing:
        raise ValueError("Chain-of-custody details missing: " + ", ".join(missing))
    acquisition_hash = clean.get("acquisition_sha256", "").lower()
    if acquisition_hash and not re.fullmatch(r"[0-9a-f]{64}", acquisition_hash):
        raise ValueError("Acquisition SHA-256 must be 64 hexadecimal characters.")
    clean["acquisition_sha256"] = acquisition_hash
    clean["hash_verified"] = None if not acquisition_hash else int(acquisition_hash == digest)
    return clean


def _store_evidence_record(connection, case_id: str, item: dict[str, Any], target: Path,
                           provenance: dict[str, Any] | None) -> None:
    digest = item["sha256"]
    connection.execute(
        """INSERT INTO evidence(
            evidence_id,case_id,filename,file_type,sha256,raw_bytes,
            extracted_text,extraction_status,metadata_json,original_path,ingested_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            item["evidence_id"], case_id, item["filename"], item["file_type"],
            digest, item["raw_bytes"], item.get("text", ""),
            item.get("extraction_status", "Unknown"),
            _json_dumps(item.get("metadata") or {}),
            _relative(target), _now(),
        ),
    )
    passages = _write_passages(connection, case_id, item["evidence_id"], item.get("text", ""))
    timeline = item.get("timeline") or []
    connection.executemany(
        "INSERT INTO timeline_events(case_id,evidence_id,ts,summary,source,fields_json) VALUES(?,?,?,?,?,?)",
        [(case_id, item["evidence_id"], str(event.get("timestamp", "")),
          str(event.get("summary", ""))[:2000], str(event.get("source", "")),
          _json_dumps(event.get("fields") or {}))
         for event in timeline if event.get("timestamp")],
    )
    if provenance:
        connection.execute(
            """INSERT INTO evidence_provenance(evidence_id,case_id,source_description,device_identifier,
                   acquired_by,acquisition_method,acquisition_tool,acquired_at,legal_authority,
                   certificate_reference,acquisition_sha256,hash_verified,notes,recorded_by,recorded_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (item["evidence_id"], case_id, provenance["source_description"],
             provenance.get("device_identifier", ""), provenance["acquired_by"],
             provenance["acquisition_method"], provenance.get("acquisition_tool", ""),
             provenance["acquired_at"], provenance["legal_authority"],
             provenance.get("certificate_reference", ""), provenance["acquisition_sha256"],
             provenance["hash_verified"], provenance.get("notes", ""), current_actor(), _now()),
        )
        _add_custody(connection, case_id, item["evidence_id"], "acquired",
                     from_party=provenance["source_description"],
                     to_party=provenance["acquired_by"], location="",
                     occurred_at=provenance["acquired_at"],
                     notes=f'Method: {provenance["acquisition_method"]}; '
                           f'authority: {provenance["legal_authority"]}')
    _add_custody(connection, case_id, item["evidence_id"], "received_into_vault",
                 from_party=(provenance or {}).get("acquired_by", ""), to_party="TRACE AI vault",
                 location="Encrypted evidence store", occurred_at=_now(),
                 notes=f"SHA-256 {digest}")
    _log(connection, case_id, "evidence_ingested", {
        "evidence_id": item["evidence_id"],
        "filename": item["filename"],
        "sha256": digest,
        "bytes": item["raw_bytes"],
        "passages": passages,
        "timeline_events": len(timeline),
        "acquisition_hash_verified": None if not provenance else provenance["hash_verified"],
        "provenance_recorded": bool(provenance),
    })
    connection.execute("DELETE FROM analysis_results WHERE case_id=?", (case_id,))
    connection.execute(
        "UPDATE investigative_leads SET status='Needs refresh',updated_at=? WHERE case_id=?",
        (_now(), case_id),
    )


def _reject_hash_mismatch(case_id: str, item: dict[str, Any], provenance: dict[str, Any]) -> None:
    with _connect() as connection:
        _log(connection, case_id, "evidence_rejected_hash_mismatch", {
            "filename": item["filename"], "uploaded_sha256": item["sha256"],
            "acquisition_sha256": provenance["acquisition_sha256"],
        })
    raise ValueError(
        f"{item['filename']}: SHA-256 of the uploaded file does not match the acquisition hash. "
        "It was not added. Re-export the file from the original acquisition or check the hash."
    )


def save_evidence(case_id: str, item: dict[str, Any], original: bytes,
                  provenance: dict[str, Any] | None = None) -> bool:
    """Persist an uploaded original (encrypted) and its extracted record for a case.

    Returns False when this case already contains the same SHA-256 digest.
    With ``provenance``, the acquisition record is validated and stored write-once;
    a supplied acquisition hash that does not match the upload is rejected.
    """
    import io
    return _save(case_id, item, lambda target: crypto.encrypt_stream(io.BytesIO(original), target),
                 provenance)


def save_evidence_from_path(case_id: str, item: dict[str, Any], source: Path,
                            provenance: dict[str, Any] | None = None) -> bool:
    """Like save_evidence, streaming a large original from disk."""
    def writer(target: Path):
        with open(source, "rb") as handle:
            return crypto.encrypt_stream(handle, target)
    return _save(case_id, item, writer, provenance)


def _save(case_id: str, item: dict[str, Any], write_encrypted, provenance) -> bool:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    digest = item["sha256"]
    clean_provenance = _validate_provenance(provenance, digest) if provenance else None
    if clean_provenance and clean_provenance["hash_verified"] == 0:
        _reject_hash_mismatch(case_id, item, clean_provenance)
    target = EVIDENCE_DIR / f"{item['evidence_id']}.enc"
    with _connect() as connection:
        if connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND sha256=?", (case_id, digest)
        ).fetchone():
            return False
    if target.exists():
        try:
            stored_digest = crypto.plaintext_sha256(target)
        except crypto.DecryptionError:
            stored_digest = None
        if stored_digest != digest:
            raise IOError(
                "An existing stored original failed its SHA-256 check. "
                "The file was left unchanged; preserve it for review."
            )
    else:
        written_digest, _ = write_encrypted(target)
        if written_digest != digest:
            target.unlink(missing_ok=True)
            raise IOError("The file changed while it was being stored. Nothing was saved.")
    with _connect() as connection:
        if connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND sha256=?", (case_id, digest)
        ).fetchone():
            return False
        _store_evidence_record(connection, case_id, item, target, clean_provenance)
    return True


def list_evidence(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT evidence_id,case_id,filename,file_type,sha256,raw_bytes,
                       extracted_text,extraction_status,metadata_json,original_path,ingested_at
               FROM evidence WHERE case_id=? ORDER BY ingested_at,evidence_id""",
            (case_id,),
        ).fetchall()
    return [
        {
            **dict(row),
            "text": row["extracted_text"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "original_path": str(_resolve_original_path(row["original_path"])),
        }
        for row in rows
    ]


def _original_row(connection, evidence_id: str, case_id: str):
    return connection.execute(
        "SELECT sha256,original_path FROM evidence WHERE evidence_id=? AND case_id=?",
        (evidence_id, case_id),
    ).fetchone()


def read_original(evidence_id: str, case_id: str) -> bytes:
    """Return the decrypted original. Raises on tampering."""
    with _connect() as connection:
        row = _original_row(connection, evidence_id, case_id)
    if row is None:
        raise ValueError("Evidence record was not found in the active case.")
    path = _resolve_original_path(row["original_path"])
    if crypto.is_encrypted_file(path):
        return crypto.decrypt_to_bytes(path)
    return path.read_bytes()


def verify_original(evidence_id: str, case_id: str) -> tuple[bool, str]:
    """Recalculate a retained original's digest without modifying the file."""
    with _connect() as connection:
        row = _original_row(connection, evidence_id, case_id)
    if row is None:
        return False, "Evidence record was not found in the active case."

    target = _resolve_original_path(row["original_path"])
    try:
        target.relative_to(EVIDENCE_DIR.resolve())
    except ValueError:
        return False, "Stored original is outside the evidence directory."
    if not target.is_file():
        return False, "Stored original is missing."

    detail = ""
    try:
        if crypto.is_encrypted_file(target):
            actual_digest = crypto.plaintext_sha256(target)
        else:
            actual_digest = _hash_file(target)
    except crypto.DecryptionError as exc:
        actual_digest, detail = None, str(exc)
    matches = actual_digest == row["sha256"]
    with _connect() as connection:
        _log(connection, case_id, "evidence_integrity_check", {
            "evidence_id": evidence_id,
            "matches": matches,
        })
    if matches:
        return True, "SHA-256 matches the value recorded at ingestion (encrypted copy authenticated)."
    if detail:
        return False, f"Encrypted original failed authentication: {detail} Preserve it and investigate."
    return False, "SHA-256 mismatch. Preserve the file and investigate before relying on it."


def _purge_evidence_rows(connection, case_id: str, evidence_id: str | None = None) -> None:
    clause, params = ("case_id=?", (case_id,)) if evidence_id is None else \
        ("case_id=? AND evidence_id=?", (case_id, evidence_id))
    for table in ("evidence_chunks", "evidence_passages", "passages_fts",
                  "timeline_events", "evidence_translations", "evidence"):
        connection.execute(f"DELETE FROM {table} WHERE {clause}", params)


def delete_evidence(case_id: str, evidence_id: str) -> dict[str, Any]:
    with _connect() as connection:
        row = connection.execute(
            """SELECT evidence_id,filename,sha256,original_path
               FROM evidence WHERE case_id=? AND evidence_id=?""",
            (case_id, evidence_id),
        ).fetchone()
        if row is None:
            raise ValueError("Evidence record was not found in the active case.")

        relative_path = row["original_path"]
        affected_leads: list[str] = []
        for lead_row in connection.execute(
            "SELECT lead_id,content_json FROM investigative_leads WHERE case_id=?",
            (case_id,),
        ).fetchall():
            content = json.loads(lead_row["content_json"])
            if evidence_id in content.get("supporting_evidence", []):
                affected_leads.append(lead_row["lead_id"])

        _purge_evidence_rows(connection, case_id, evidence_id)
        connection.execute("DELETE FROM analysis_results WHERE case_id=?", (case_id,))
        for lead_id in affected_leads:
            connection.execute(
                "UPDATE investigative_leads SET status='Needs refresh',updated_at=? "
                "WHERE case_id=? AND lead_id=?",
                (_now(), case_id, lead_id),
            )
        _add_custody(connection, case_id, evidence_id, "removed_from_vault",
                     from_party="TRACE AI vault", to_party="", location="",
                     occurred_at=_now(), notes="Working copy deleted by an authorized user.")
        _log(connection, case_id, "evidence_deleted", {
            "evidence_id": evidence_id,
            "filename": row["filename"],
            "sha256": row["sha256"],
            "affected_leads": affected_leads,
        })
        removable = _originals_to_remove(connection, [relative_path])

    removed, warnings = _unlink_files(removable)
    return {
        "evidence_id": evidence_id,
        "filename": row["filename"],
        "original_removed": bool(removed),
        "file_warnings": warnings,
        "affected_leads": affected_leads,
    }


def delete_case(case_id: str) -> dict[str, Any]:
    """Remove a case's evidence and working data. The signed audit trail is kept."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT case_id,name FROM cases WHERE case_id=? AND deleted_at IS NULL", (case_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Case was not found.")
        case_count = connection.execute(
            "SELECT COUNT(*) FROM cases WHERE deleted_at IS NULL"
        ).fetchone()[0]
        if case_count <= 1:
            raise ValueError("At least one case must remain in the workspace.")

        relative_paths = [
            item["original_path"]
            for item in connection.execute(
                "SELECT original_path FROM evidence WHERE case_id=?", (case_id,)
            ).fetchall()
        ]
        evidence_count = len(relative_paths)
        _purge_evidence_rows(connection, case_id)
        for table in ("chat_messages", "investigative_leads", "analysis_results",
                      "reports", "case_members"):
            connection.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
        connection.execute(
            "UPDATE cases SET deleted_at=?,deleted_by=? WHERE case_id=?",
            (_now(), current_actor(), case_id),
        )
        _log(connection, case_id, "case_deleted", {"name": row["name"], "evidence_count": evidence_count})
        removable = _originals_to_remove(connection, relative_paths)

    removed, warnings = _unlink_files(removable)
    return {
        "case_id": case_id,
        "name": row["name"],
        "evidence_count": evidence_count,
        "files_removed": removed,
        "file_warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# Provenance and custody
# --------------------------------------------------------------------------- #
CUSTODY_ACTIONS = ("acquired", "received_into_vault", "transferred", "examined",
                   "copied_for_analysis", "sealed", "returned", "removed_from_vault", "correction")


def _add_custody(connection, case_id: str, evidence_id: str, action: str, *, from_party: str,
                 to_party: str, location: str, occurred_at: str, notes: str) -> None:
    connection.execute(
        """INSERT INTO custody_events(case_id,evidence_id,action,from_party,to_party,location,
               occurred_at,notes,recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (case_id, evidence_id, action, from_party, to_party, location, occurred_at, notes,
         current_actor(), _now()),
    )
    _log(connection, case_id, f"custody_{action}", {
        "evidence_id": evidence_id, "from": from_party, "to": to_party,
        "location": location, "occurred_at": occurred_at, "notes": notes,
    })


def add_custody_event(case_id: str, evidence_id: str, action: str, from_party: str = "",
                      to_party: str = "", location: str = "", occurred_at: str = "",
                      notes: str = "") -> None:
    if action not in CUSTODY_ACTIONS:
        raise ValueError("Unknown custody action.")
    with _connect() as connection:
        if not connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence_id)
        ).fetchone():
            raise ValueError("Evidence record was not found in the active case.")
        _add_custody(connection, case_id, evidence_id, action, from_party=from_party.strip(),
                     to_party=to_party.strip(), location=location.strip(),
                     occurred_at=occurred_at or _now(), notes=notes.strip())


def get_provenance(evidence_id: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM evidence_provenance WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
    return dict(row) if row else None


def record_provenance(case_id: str, evidence_id: str, provenance: dict[str, Any]) -> None:
    """Add the acquisition record for evidence ingested without one (write-once)."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence_id)
        ).fetchone()
        if row is None:
            raise ValueError("Evidence record was not found in the active case.")
        if connection.execute("SELECT 1 FROM evidence_provenance WHERE evidence_id=?", (evidence_id,)).fetchone():
            raise ValueError("Provenance is already recorded; add a 'correction' custody event instead.")
        clean = _validate_provenance(provenance, row["sha256"])
        connection.execute(
            """INSERT INTO evidence_provenance(evidence_id,case_id,source_description,device_identifier,
                   acquired_by,acquisition_method,acquisition_tool,acquired_at,legal_authority,
                   certificate_reference,acquisition_sha256,hash_verified,notes,recorded_by,recorded_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (evidence_id, case_id, clean["source_description"], clean.get("device_identifier", ""),
             clean["acquired_by"], clean["acquisition_method"], clean.get("acquisition_tool", ""),
             clean["acquired_at"], clean["legal_authority"], clean.get("certificate_reference", ""),
             clean["acquisition_sha256"], clean["hash_verified"], clean.get("notes", ""),
             current_actor(), _now()),
        )
        _log(connection, case_id, "provenance_recorded_after_ingest", {
            "evidence_id": evidence_id, "hash_verified": clean["hash_verified"],
            "legal_authority": clean["legal_authority"],
        })


def list_custody(evidence_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY event_id", (evidence_id,)
        ).fetchall()
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------- #
# Chat
# --------------------------------------------------------------------------- #
def save_chat_message(case_id: str, role: str, content: str,
                      sources: list[dict[str, Any]] | None = None,
                      retrieval_query: str = "", meta: dict[str, Any] | None = None) -> None:
    if role not in {"user", "assistant"}:
        raise ValueError("Unsupported chat role.")
    with _connect() as connection:
        connection.execute(
            "INSERT INTO chat_messages(case_id,role,content,sources_json,retrieval_query,created_at,meta_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (case_id, role, content, _json_dumps(sources or []), retrieval_query, _now(),
             _json_dumps(meta or {})),
        )


def list_chat_messages(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT role,content,sources_json,retrieval_query,meta_json FROM chat_messages "
            "WHERE case_id=? ORDER BY message_id",
            (case_id,),
        ).fetchall()
    return [
        {"role": row["role"], "content": row["content"],
         "sources": json.loads(row["sources_json"]),
         "retrieval_query": row["retrieval_query"],
         "meta": json.loads(row["meta_json"] or "{}")}
        for row in rows
    ]


def clear_chat(case_id: str) -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM chat_messages WHERE case_id=?", (case_id,))
        _log(connection, case_id, "chat_cleared")


# --------------------------------------------------------------------------- #
# Leads and analysis
# --------------------------------------------------------------------------- #
def save_leads(case_id: str, leads: list[dict[str, Any]]) -> None:
    timestamp = _now()
    with _connect() as connection:
        for lead in leads:
            connection.execute(
                """INSERT INTO investigative_leads
                   (lead_id,case_id,type,content_json,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(lead_id) DO UPDATE SET
                        content_json=excluded.content_json,
                        type=excluded.type,
                        updated_at=excluded.updated_at""",
                (lead["lead_id"], case_id, lead["type"],
                 _json_dumps(lead), lead.get("status", "Unreviewed"),
                 timestamp, timestamp),
            )
        if leads:
            _log(connection, case_id, "investigative_leads_generated", {"count": len(leads)})


def list_leads(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT content_json,status FROM investigative_leads WHERE case_id=? ORDER BY created_at,lead_id",
            (case_id,),
        ).fetchall()
    result = []
    for row in rows:
        lead = json.loads(row["content_json"])
        lead["status"] = row["status"]
        result.append(lead)
    return result


def update_lead_status(case_id: str, lead_id: str, status: str) -> None:
    with _connect() as connection:
        connection.execute(
            "UPDATE investigative_leads SET status=?,updated_at=? WHERE case_id=? AND lead_id=?",
            (status, _now(), case_id, lead_id),
        )
        _log(connection, case_id, "lead_status_updated", {"lead_id": lead_id, "status": status})


def save_analysis_result(case_id: str, analysis_type: str, result: dict[str, Any]) -> None:
    with _connect() as connection:
        connection.execute(
            """INSERT INTO analysis_results(case_id,analysis_type,result_json,updated_at)
               VALUES(?,?,?,?) ON CONFLICT(case_id,analysis_type) DO UPDATE SET
               result_json=excluded.result_json,updated_at=excluded.updated_at""",
            (case_id, analysis_type, _json_dumps(result), _now()),
        )
        _log(connection, case_id, f"{analysis_type}_analysis_completed", {})


def load_analysis_result(case_id: str, analysis_type: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM analysis_results WHERE case_id=? AND analysis_type=?",
            (case_id, analysis_type),
        ).fetchone()
    return json.loads(row["result_json"]) if row else None


# --------------------------------------------------------------------------- #
# Reports (persistent, versioned)
# --------------------------------------------------------------------------- #
def save_report(case_id: str, kind: str, title: str, content: str, language: str = "English",
                evidence_ids: list[str] | None = None,
                verification: dict[str, Any] | None = None) -> str:
    report_id = "RPT-" + uuid.uuid4().hex[:12].upper()
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO reports(report_id,case_id,kind,title,language,content,evidence_ids_json,
                   verification_json,sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (report_id, case_id, kind, title, language, content, _json_dumps(sorted(evidence_ids or [])),
             _json_dumps(verification or {}), digest, current_actor(), _now()),
        )
        _log(connection, case_id, "report_saved", {
            "report_id": report_id, "kind": kind, "sha256": digest,
            "evidence_ids": sorted(evidence_ids or []),
        })
    return report_id


def list_reports(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM reports WHERE case_id=? ORDER BY created_at DESC", (case_id,)
        ).fetchall()
    return [
        {**dict(row), "evidence_ids": json.loads(row["evidence_ids_json"]),
         "verification": json.loads(row["verification_json"])}
        for row in rows
    ]


# --------------------------------------------------------------------------- #
# Search support: passages / FTS5, timeline, translations
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"[\wऀ-ॿ]+", re.UNICODE)


def fts_query_string(query: str) -> str:
    tokens = [token for token in _TOKEN_RE.findall(query or "") if len(token) > 1][:32]
    return " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)


def search_passages_fts(case_id: str, query: str, limit: int = 200) -> list[dict[str, Any]]:
    match = fts_query_string(query)
    if not match:
        return []
    with _connect() as connection:
        rows = connection.execute(
            """SELECT f.evidence_id,f.chunk_id,f.text,bm25(passages_fts) AS rank,e.filename
               FROM passages_fts f JOIN evidence e
                 ON e.evidence_id=f.evidence_id AND e.case_id=f.case_id
               WHERE passages_fts MATCH ? AND f.case_id=? ORDER BY rank LIMIT ?""",
            (match, case_id, limit),
        ).fetchall()
    return [
        {"evidence_id": row["evidence_id"], "chunk_id": int(row["chunk_id"]),
         "snippet": row["text"], "filename": row["filename"], "bm25": -float(row["rank"])}
        for row in rows
    ]


def count_passages(case_id: str) -> int:
    with _connect() as connection:
        return int(connection.execute(
            "SELECT COUNT(*) FROM evidence_passages WHERE case_id=?", (case_id,)
        ).fetchone()[0])


def get_passage(case_id: str, evidence_id: str, chunk_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            """SELECT p.evidence_id,p.chunk_id,p.text,e.filename FROM evidence_passages p
               JOIN evidence e ON e.evidence_id=p.evidence_id
               WHERE p.case_id=? AND p.evidence_id=? AND p.chunk_id=?""",
            (case_id, evidence_id, chunk_id),
        ).fetchone()
    return ({"evidence_id": row["evidence_id"], "chunk_id": row["chunk_id"],
             "snippet": row["text"], "filename": row["filename"]} if row else None)


def query_timeline(case_id: str, start: str | None = None, end: str | None = None,
                   keyword: str | None = None, evidence_id: str | None = None,
                   limit: int = 200) -> list[dict[str, Any]]:
    query = "SELECT evidence_id,ts,summary,source,fields_json FROM timeline_events WHERE case_id=?"
    params: list[Any] = [case_id]
    if start:
        query += " AND ts >= ?"
        params.append(start)
    if end:
        query += " AND ts <= ?"
        params.append(end)
    if evidence_id:
        query += " AND evidence_id=?"
        params.append(evidence_id)
    if keyword:
        query += " AND (summary LIKE ? OR fields_json LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    query += " ORDER BY ts LIMIT ?"
    params.append(int(limit))
    with _connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [{**dict(row), "fields": json.loads(row["fields_json"])} for row in rows]


def count_timeline(case_id: str) -> int:
    with _connect() as connection:
        return int(connection.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE case_id=?", (case_id,)
        ).fetchone()[0])


def save_translation(case_id: str, evidence_id: str, language: str, text: str, model: str) -> None:
    with _connect() as connection:
        connection.execute(
            """INSERT INTO evidence_translations(evidence_id,case_id,language,text,model,created_at)
               VALUES(?,?,?,?,?,?) ON CONFLICT(evidence_id,language) DO UPDATE SET
               text=excluded.text,model=excluded.model,created_at=excluded.created_at""",
            (evidence_id, case_id, language, text, model, _now()),
        )
        _log(connection, case_id, "evidence_translated", {
            "evidence_id": evidence_id, "language": language, "model": model,
            "note": "Machine translation; the original text remains the evidence.",
        })


def get_translation(evidence_id: str, language: str) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT text,model,created_at FROM evidence_translations WHERE evidence_id=? AND language=?",
            (evidence_id, language),
        ).fetchone()
    return dict(row) if row else None


# --------------------------------------------------------------------------- #
# Semantic chunks
# --------------------------------------------------------------------------- #
def _prepare_chunk_rows(case_id: str, evidence_id: str, model_name: str,
                        chunks: list[dict[str, Any]], vectors: list[Any]) -> tuple[list[tuple], str]:
    if len(chunks) != len(vectors):
        raise ValueError("Each chunk must have exactly one embedding vector.")
    timestamp = _now()
    rows = []
    for chunk, vector in zip(chunks, vectors):
        raw_vector = vector.tobytes() if hasattr(vector, "tobytes") else bytes(vector)
        dimension = int(len(vector))
        rows.append((case_id, evidence_id, int(chunk["chunk_id"]), chunk["text"],
                     model_name, dimension, raw_vector, timestamp))
    return rows, timestamp


def _write_chunk_rows(connection, case_id: str, evidence_id: str,
                      model_name: str, rows: list[tuple], timestamp: str) -> None:
    connection.execute(
        "DELETE FROM evidence_chunks WHERE case_id=? AND evidence_id=? AND model_name=?",
        (case_id, evidence_id, model_name),
    )
    connection.executemany(
        """INSERT INTO evidence_chunks
           (case_id,evidence_id,chunk_id,chunk_text,model_name,dimension,embedding,indexed_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        rows,
    )
    _log(connection, case_id, "evidence_semantic_indexed", {
        "evidence_id": evidence_id, "chunks": len(rows), "model": model_name,
    })


def replace_evidence_chunks(case_id: str, evidence_id: str, model_name: str,
                            chunks: list[dict[str, Any]], vectors: list[Any]) -> None:
    rows, timestamp = _prepare_chunk_rows(case_id, evidence_id, model_name, chunks, vectors)
    with _connect() as connection:
        _write_chunk_rows(connection, case_id, evidence_id, model_name, rows, timestamp)


def replace_many_evidence_chunks(entries: list[tuple[str, str, str, list[dict[str, Any]], list[Any]]]) -> None:
    """Replace all supplied chunk sets in one transaction."""
    prepared = [
        (case_id, evidence_id, model_name, *_prepare_chunk_rows(
            case_id, evidence_id, model_name, chunks, vectors
        ))
        for case_id, evidence_id, model_name, chunks, vectors in entries
    ]
    with _connect() as connection:
        for case_id, evidence_id, model_name, rows, timestamp in prepared:
            _write_chunk_rows(connection, case_id, evidence_id, model_name, rows, timestamp)


def list_evidence_chunks(case_id: str, model_name: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT evidence_id,chunk_id,chunk_text,dimension,embedding
               FROM evidence_chunks WHERE case_id=? AND model_name=? ORDER BY evidence_id,chunk_id""",
            (case_id, model_name),
        ).fetchall()
    return [dict(row) for row in rows]


def count_evidence_chunks(case_id: str, model_name: str) -> int:
    with _connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM evidence_chunks WHERE case_id=? AND model_name=?",
            (case_id, model_name),
        ).fetchone()
    return int(row["total"])


def chunk_index_version(case_id: str, model_name: str) -> tuple[int, str]:
    """(count, latest indexed_at): changes whenever the semantic index changes."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*),COALESCE(MAX(indexed_at),'') FROM evidence_chunks WHERE case_id=? AND model_name=?",
            (case_id, model_name),
        ).fetchone()
    return int(row[0]), str(row[1])
