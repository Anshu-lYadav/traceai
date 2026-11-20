"""Persistent background job queue for heavy work.

Jobs live in the encrypted database (``jobs`` table) so they survive restarts
(running jobs are re-queued on startup). A small pool of daemon worker threads
in the Streamlit server process claims and runs them, so uploads of large PDFs,
OCR, PCAP/EVTX parsing, disk/memory images, semantic indexing and translation
no longer block the page. Uploaded bytes wait in ``data/staging`` encrypted with
the same AES-GCM format as evidence and are removed after ingestion.

Handlers run with the submitting officer as the audit actor.
"""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable

from modules import crypto, database

WORKERS = int(os.environ.get("TRACE_JOB_WORKERS", "2"))
POLL_SECONDS = 1.0

_handlers: dict[str, Callable[[dict[str, Any], Callable[[float, str], None]], dict[str, Any]]] = {}
_started = False
_start_lock = threading.Lock()


def staging_dir() -> Path:
    path = database.DATA_DIR / "staging"
    path.mkdir(parents=True, exist_ok=True)
    return path


def handler(kind: str):
    def register(function):
        _handlers[kind] = function
        return function
    return register


def enqueue(kind: str, case_id: str, payload: dict[str, Any], created_by: str) -> str:
    if kind not in _handlers:
        raise ValueError(f"Unknown job kind {kind!r}")
    job_id = "JOB-" + uuid.uuid4().hex[:12].upper()
    with database._connect() as connection:
        connection.execute(
            """INSERT INTO jobs(job_id,case_id,kind,status,payload_json,created_by,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (job_id, case_id, kind, "queued", database._json_dumps(payload), created_by, database._now()),
        )
        database._append_audit(connection, case_id, "job_queued", {"job_id": job_id, "kind": kind,
                                                                    "label": payload.get("label", "")},
                               actor=created_by)
    ensure_workers()
    return job_id


def stage_upload(raw: bytes) -> str:
    """Encrypt uploaded bytes into the staging area; returns the staging token."""
    token = uuid.uuid4().hex
    crypto.encrypt_bytes(raw, staging_dir() / f"{token}.enc")
    return token


def list_jobs(case_id: str, limit: int = 30) -> list[dict[str, Any]]:
    with database._connect() as connection:
        rows = connection.execute(
            "SELECT job_id,kind,status,progress,message,error,result_json,payload_json,created_by,"
            "created_at,started_at,finished_at FROM jobs WHERE case_id=? ORDER BY created_at DESC LIMIT ?",
            (case_id, limit),
        ).fetchall()
    jobs = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        jobs.append({**{k: row[k] for k in row.keys() if k not in {"payload_json", "result_json"}},
                     "label": payload.get("label", row["kind"]),
                     "result": json.loads(row["result_json"] or "{}")})
    return jobs


def active_job_count(case_id: str) -> int:
    with database._connect() as connection:
        return int(connection.execute(
            "SELECT COUNT(*) FROM jobs WHERE case_id=? AND status IN ('queued','running')", (case_id,)
        ).fetchone()[0])


def _claim() -> dict[str, Any] | None:
    with database._connect() as connection:
        row = connection.execute(
            "SELECT job_id FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if not row:
            return None
        updated = connection.execute(
            "UPDATE jobs SET status='running',started_at=?,progress=0,message='Started' "
            "WHERE job_id=? AND status='queued'",
            (database._now(), row["job_id"]),
        ).rowcount
        if not updated:
            return None
        job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (row["job_id"],)).fetchone()
    return dict(job)


def _update(job_id: str, **fields: Any) -> None:
    assignments = ",".join(f"{key}=?" for key in fields)
    with database._connect() as connection:
        connection.execute(f"UPDATE jobs SET {assignments} WHERE job_id=?", (*fields.values(), job_id))


def run_job(job: dict[str, Any]) -> None:
    job_id = job["job_id"]
    payload = json.loads(job["payload_json"])
    last = {"t": 0.0}

    def progress(fraction: float, message: str = "") -> None:
        now = time.monotonic()
        if now - last["t"] > 0.5 or fraction >= 1:
            last["t"] = now
            _update(job_id, progress=float(max(0.0, min(fraction, 1.0))), message=message[:300])

    with database.acting_as(job["created_by"]):
        try:
            result = _handlers[job["kind"]]({**payload, "case_id": job["case_id"]}, progress)
            _update(job_id, status="done", progress=1.0, message="Completed",
                    result_json=database._json_dumps(result or {}), finished_at=database._now())
            database.log_activity(job["case_id"], "job_completed", {"job_id": job_id, "kind": job["kind"]})
        except Exception as exc:
            _update(job_id, status="failed", error=f"{exc}"[:2000], finished_at=database._now(),
                    message="Failed")
            database.log_activity(job["case_id"], "job_failed", {
                "job_id": job_id, "kind": job["kind"], "error": str(exc)[:500],
                "trace": traceback.format_exc(limit=3)[-800:],
            })


def run_pending_once() -> bool:
    """Run one queued job in the calling thread (used by tests and the worker)."""
    job = _claim()
    if job is None:
        return False
    run_job(job)
    return True


def _worker_loop() -> None:
    while True:
        try:
            if not run_pending_once():
                time.sleep(POLL_SECONDS)
        except Exception:
            time.sleep(POLL_SECONDS * 5)


def ensure_workers() -> None:
    global _started
    if os.environ.get("TRACE_DISABLE_WORKERS") == "1":
        return
    with _start_lock:
        if _started:
            return
        for index in range(max(1, WORKERS)):
            threading.Thread(target=_worker_loop, name=f"trace-job-worker-{index}", daemon=True).start()
        _started = True


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
class _StagedUpload:
    def __init__(self, name: str, raw: bytes):
        self.name = name
        self._raw = raw

    def getvalue(self) -> bytes:
        return self._raw


@handler("ingest_upload")
def _ingest_upload(payload: dict[str, Any], progress) -> dict[str, Any]:
    from modules.evidence_processor import process_upload

    staged = staging_dir() / f"{payload['staging_token']}.enc"
    try:
        progress(0.05, "Decrypting staged upload")
        raw = crypto.decrypt_to_bytes(staged)
        progress(0.15, "Extracting text, OCR and forensic artefacts")
        item = process_upload(_StagedUpload(payload["filename"], raw), payload["case_id"])
        progress(0.85, "Encrypting original and indexing")
        added = database.save_evidence(payload["case_id"], item, raw, payload.get("provenance"))
        return {"evidence_id": item["evidence_id"], "added": added,
                "status": item["extraction_status"], "duplicate": not added}
    finally:
        staged.unlink(missing_ok=True)


@handler("ingest_path")
def _ingest_path(payload: dict[str, Any], progress) -> dict[str, Any]:
    from modules.evidence_processor import process_path

    source = Path(payload["path"])
    allowed_roots = [Path(p).resolve() for p in os.environ.get(
        "TRACE_IMPORT_DIRS", str(database.DATA_DIR / "import")).split(os.pathsep) if p]
    resolved = source.resolve()
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise PermissionError("Server-side imports are only allowed from TRACE_IMPORT_DIRS "
                              f"({', '.join(str(r) for r in allowed_roots)}).")
    if not resolved.is_file():
        raise FileNotFoundError(f"{resolved} was not found on the server.")
    item = process_path(resolved, payload["case_id"], payload.get("filename") or resolved.name,
                        progress=lambda f, m="": progress(0.05 + 0.75 * f, m))
    progress(0.85, "Encrypting original into the vault")
    added = database.save_evidence_from_path(payload["case_id"], item, resolved, payload.get("provenance"))
    return {"evidence_id": item["evidence_id"], "added": added, "status": item["extraction_status"]}


@handler("build_index")
def _build_index(payload: dict[str, Any], progress) -> dict[str, Any]:
    from modules.search_engine import build_semantic_index

    evidence = database.list_evidence(payload["case_id"])
    return build_semantic_index(evidence, progress=progress)


@handler("translate_evidence")
def _translate(payload: dict[str, Any], progress) -> dict[str, Any]:
    from modules.llm_engine import MODEL_NAME, translate_text

    items = [i for i in database.list_evidence(payload["case_id"]) if i["evidence_id"] == payload["evidence_id"]]
    if not items:
        raise ValueError("Evidence not found.")
    text = translate_text(items[0]["text"][:200_000], payload["language"],
                          progress=lambda f: progress(f, "Translating"))
    database.save_translation(payload["case_id"], payload["evidence_id"], payload["language"], text, MODEL_NAME)
    return {"characters": len(text)}
