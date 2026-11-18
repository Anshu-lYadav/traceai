"""Local SQLite persistence for cases, evidence, conversations, and activity."""

from __future__ import annotations

import json
import hashlib
import math
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DATABASE_PATH = DATA_DIR / "trace_ai.db"


@contextmanager
def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
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


def _originals_to_remove(connection: sqlite3.Connection,
                         relative_paths: list[str]) -> list[Path]:
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


def initialize_database() -> None:
    """Create or upgrade the local schema. Safe to call at app startup."""
    with _connect() as connection:
        connection.executescript(
            """
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

            CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
            CREATE INDEX IF NOT EXISTS idx_chat_case ON chat_messages(case_id, message_id);
            CREATE INDEX IF NOT EXISTS idx_activity_case ON activity_log(case_id, activity_id);
            """
        )
        chat_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(chat_messages)").fetchall()
        }
        if "retrieval_query" not in chat_columns:
            connection.execute(
                "ALTER TABLE chat_messages ADD COLUMN retrieval_query TEXT NOT NULL DEFAULT ''"
            )
        evidence_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(evidence)").fetchall()
        }
        if "metadata_json" not in evidence_columns:
            connection.execute(
                "ALTER TABLE evidence ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"
            )
        connection.execute(
            "UPDATE evidence SET original_path = REPLACE(original_path, '\\', '/') "
            "WHERE original_path LIKE '%\\%'"
        )


def _log(connection: sqlite3.Connection, case_id: str, event_type: str,
         details: dict[str, Any] | None = None) -> None:
    connection.execute(
        "INSERT INTO activity_log(case_id,event_type,details_json,created_at) VALUES(?,?,?,?)",
        (case_id, event_type, _json_dumps(details or {}), _now()),
    )


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


def create_case(case_id: str, name: str, description: str = "") -> None:
    case_id = case_id.strip()
    name = name.strip()
    if not case_id or not name:
        raise ValueError("Case ID and case name are required.")
    timestamp = _now()
    with _connect() as connection:
        connection.execute(
            "INSERT INTO cases(case_id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)",
            (case_id, name, description.strip(), timestamp, timestamp),
        )
        _log(connection, case_id, "case_created", {"name": name})


def ensure_default_case() -> None:
    with _connect() as connection:
        exists = connection.execute("SELECT 1 FROM cases LIMIT 1").fetchone()
        if not exists:
            timestamp = _now()
            connection.execute(
                "INSERT INTO cases(case_id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("CASE-001", "Default Investigation", "", timestamp, timestamp),
            )
            _log(connection, "CASE-001", "case_created", {"name": "Default Investigation"})


def list_cases() -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT case_id,name,description,created_at,updated_at FROM cases ORDER BY created_at,case_id"
        ).fetchall()
    return [dict(row) for row in rows]


def save_evidence(case_id: str, item: dict[str, Any], original: bytes) -> bool:
    """Persist an uploaded original once and its extracted record for a case.

    Returns False when this case already contains the same SHA-256 digest.
    Each case gets its own original file, named only from the case-derived
    evidence ID, never from an investigator-supplied filename.
    """
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    digest = item["sha256"]
    original_path = EVIDENCE_DIR / f"{item['evidence_id']}.bin"

    with _connect() as connection:
        existing = connection.execute(
            "SELECT 1 FROM evidence WHERE case_id=? AND sha256=?",
            (case_id, digest),
        ).fetchone()
        if existing:
            return False

        if original_path.exists():
            stored_digest = _hash_file(original_path)
            if stored_digest != digest:
                raise IOError(
                    "An existing stored original failed its SHA-256 check. "
                    "The file was left unchanged; preserve it for review."
                )
        else:
            original_path.write_bytes(original)

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
                original_path.relative_to(PROJECT_ROOT).as_posix(), _now(),
            ),
        )
        _log(connection, case_id, "evidence_ingested", {
            "evidence_id": item["evidence_id"],
            "filename": item["filename"],
            "sha256": digest,
        })
        connection.execute(
            "DELETE FROM analysis_results WHERE case_id=?", (case_id,)
        )
        connection.execute(
            "UPDATE investigative_leads SET status='Needs refresh',updated_at=? WHERE case_id=?",
            (_now(), case_id),
        )
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


def verify_original(evidence_id: str, case_id: str) -> tuple[bool, str]:
    """Recalculate a retained original's digest without modifying the file."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT sha256,original_path FROM evidence WHERE evidence_id=? AND case_id=?",
            (evidence_id, case_id),
        ).fetchone()
    if row is None:
        return False, "Evidence record was not found in the active case."

    target = _resolve_original_path(row["original_path"])
    try:
        target.relative_to(EVIDENCE_DIR.resolve())
    except ValueError:
        return False, "Stored original is outside the evidence directory."
    if not target.is_file():
        return False, "Stored original is missing."

    actual_digest = _hash_file(target)
    matches = actual_digest == row["sha256"]
    with _connect() as connection:
        _log(connection, case_id, "evidence_integrity_check", {
            "evidence_id": evidence_id,
            "matches": matches,
        })
    return matches, "SHA-256 matches the value recorded at ingestion." if matches else "SHA-256 mismatch. Preserve the file and investigate before relying on it."


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

        connection.execute(
            "DELETE FROM evidence_chunks WHERE case_id=? AND evidence_id=?",
            (case_id, evidence_id),
        )
        connection.execute(
            "DELETE FROM evidence WHERE case_id=? AND evidence_id=?",
            (case_id, evidence_id),
        )
        connection.execute("DELETE FROM analysis_results WHERE case_id=?", (case_id,))
        for lead_id in affected_leads:
            connection.execute(
                "UPDATE investigative_leads SET status='Needs refresh',updated_at=? "
                "WHERE case_id=? AND lead_id=?",
                (_now(), case_id, lead_id),
            )
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
    with _connect() as connection:
        row = connection.execute(
            "SELECT case_id,name FROM cases WHERE case_id=?", (case_id,)
        ).fetchone()
        if row is None:
            raise ValueError("Case was not found.")
        case_count = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        if case_count <= 1:
            raise ValueError("At least one case must remain in the workspace.")

        relative_paths = [
            item["original_path"]
            for item in connection.execute(
                "SELECT original_path FROM evidence WHERE case_id=?", (case_id,)
            ).fetchall()
        ]
        evidence_count = len(relative_paths)
        for table in (
            "evidence_chunks", "evidence", "chat_messages",
            "investigative_leads", "analysis_results", "activity_log",
        ):
            connection.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
        connection.execute("DELETE FROM cases WHERE case_id=?", (case_id,))
        removable = _originals_to_remove(connection, relative_paths)

    removed, warnings = _unlink_files(removable)
    return {
        "case_id": case_id,
        "name": row["name"],
        "evidence_count": evidence_count,
        "files_removed": removed,
        "file_warnings": warnings,
    }


def save_chat_message(case_id: str, role: str, content: str,
                      sources: list[dict[str, Any]] | None = None,
                      retrieval_query: str = "") -> None:
    if role not in {"user", "assistant"}:
        raise ValueError("Unsupported chat role.")
    with _connect() as connection:
        connection.execute(
            "INSERT INTO chat_messages(case_id,role,content,sources_json,retrieval_query,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, role, content, _json_dumps(sources or []), retrieval_query, _now()),
        )


def list_chat_messages(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT role,content,sources_json,retrieval_query FROM chat_messages WHERE case_id=? ORDER BY message_id",
            (case_id,),
        ).fetchall()
    return [
        {"role": row["role"], "content": row["content"],
         "sources": json.loads(row["sources_json"]),
         "retrieval_query": row["retrieval_query"]}
        for row in rows
    ]


def clear_chat(case_id: str) -> None:
    with _connect() as connection:
        connection.execute("DELETE FROM chat_messages WHERE case_id=?", (case_id,))
        _log(connection, case_id, "chat_cleared")


def log_activity(case_id: str, event_type: str, details: dict[str, Any]) -> None:
    with _connect() as connection:
        _log(connection, case_id, event_type, details)


def list_activity(case_id: str) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT event_type,details_json,created_at FROM activity_log WHERE case_id=? ORDER BY activity_id",
            (case_id,),
        ).fetchall()
    return [
        {"event_type": row["event_type"], "details": json.loads(row["details_json"]),
         "created_at": row["created_at"]}
        for row in rows
    ]


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


def _write_chunk_rows(connection: sqlite3.Connection, case_id: str, evidence_id: str,
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

