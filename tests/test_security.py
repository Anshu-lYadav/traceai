import hashlib
import json
import os
import sqlite3 as plain_sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["TRACE_DISABLE_WORKERS"] = "1"

from modules import access, auth, crypto, database, jobs, search_engine  # noqa: E402
from modules.agent import run_agent  # noqa: E402
from modules.claim_verifier import verify_answer  # noqa: E402
from modules.evidence_processor import process_upload  # noqa: E402
from modules.llm_engine import verify_generated_text  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
_KEY_DIR = tempfile.TemporaryDirectory()


def setUpModule():
    crypto.KEY_DIR = Path(_KEY_DIR.name)


class Upload:
    def __init__(self, name, content):
        self.name, self._content = name, content

    def getvalue(self):
        return self._content


PROVENANCE = {
    "source_description": "Phone seized from complainant", "acquired_by": "SI Test (B-1)",
    "acquisition_method": "Logical extraction (device)", "acquired_at": "2026-11-01T10:00:00+05:30",
    "legal_authority": "FIR 12/2026",
}


class TempDB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            patch.object(database, "PROJECT_ROOT", root),
            patch.object(database, "DATA_DIR", root / "data"),
            patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
            patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
        ]
        for item in self.patches:
            item.start()
        database.initialize_database()
        auth.initialize_auth()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def add(self, case_id, name, content, provenance=None):
        item = process_upload(Upload(name, content), case_id)
        database.save_evidence(case_id, item, content, provenance)
        return item


class EncryptionTests(TempDB):
    def test_database_and_evidence_are_encrypted_at_rest(self):
        database.create_case("C1", "Case")
        secret = b"SECRET-PAYROLL-TRANSFER-9876543210"
        item = self.add("C1", "note.txt", secret)
        self.assertNotEqual(database.DATABASE_PATH.read_bytes()[:16], b"SQLite format 3\x00")
        self.assertNotIn(b"SECRET-PAYROLL", database.DATABASE_PATH.read_bytes())
        stored = Path(database.list_evidence("C1")[0]["original_path"])
        self.assertNotIn(b"SECRET-PAYROLL", stored.read_bytes())
        self.assertEqual(database.read_original(item["evidence_id"], "C1"), secret)
        with self.assertRaises(Exception):
            plain_sqlite3.connect(database.DATABASE_PATH).execute("SELECT * FROM evidence").fetchall()

    def test_tampered_ciphertext_fails_verification(self):
        database.create_case("C1", "Case")
        item = self.add("C1", "note.txt", b"original bytes" * 1000)
        path = Path(database.list_evidence("C1")[0]["original_path"])
        data = bytearray(path.read_bytes())
        data[200] ^= 0x01
        path.write_bytes(bytes(data))
        ok, message = database.verify_original(item["evidence_id"], "C1")
        self.assertFalse(ok)
        self.assertIn("authentication", message)

    def test_large_stream_round_trip_and_truncation_detected(self):
        target = Path(self.tmp.name) / "big.enc"
        payload = os.urandom(crypto.CHUNK_SIZE * 2 + 123)
        digest, size = crypto.encrypt_bytes(payload, target)
        self.assertEqual((digest, size), (hashlib.sha256(payload).hexdigest(), len(payload)))
        self.assertEqual(crypto.decrypt_to_bytes(target), payload)
        target.write_bytes(target.read_bytes()[: -(crypto.CHUNK_SIZE + 28)])
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_to_bytes(target)

    def test_plaintext_database_and_originals_are_migrated(self):
        database.DATABASE_PATH.unlink()
        evidence_dir = database.EVIDENCE_DIR
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "EV-OLD.bin").write_bytes(b"legacy evidence")
        connection = plain_sqlite3.connect(database.DATABASE_PATH)
        connection.executescript(database._SCHEMA.split("CREATE VIRTUAL TABLE")[0])
        now = "2025-01-01T00:00:00+00:00"
        connection.execute("INSERT INTO cases(case_id,name,description,created_at,updated_at) VALUES('OLD','Old','',?,?)", (now, now))
        connection.execute(
            "INSERT INTO evidence VALUES('EV-OLD','OLD','a.txt','txt',?,15,'legacy evidence','ok','{}','data/evidence/EV-OLD.bin',?)",
            (hashlib.sha256(b"legacy evidence").hexdigest(), now))
        connection.execute("INSERT INTO activity_log(case_id,event_type,details_json,created_at) VALUES('OLD','case_created','{}',?)", (now,))
        connection.commit()
        connection.close()

        database.initialize_database()

        self.assertNotEqual(database.DATABASE_PATH.read_bytes()[:16], b"SQLite format 3\x00")
        self.assertTrue((database.DATA_DIR / "pre_encryption_backup" / "test.db").exists())
        self.assertTrue(database.verify_original("EV-OLD", "OLD")[0])
        self.assertTrue(database.list_evidence("OLD")[0]["original_path"].endswith(".enc"))
        self.assertIn("case_created", [e["event_type"] for e in database.list_activity("OLD")])
        self.assertTrue(database.verify_audit_chain()["valid"])


class AuditChainTests(TempDB):
    def test_chain_is_signed_and_append_only(self):
        database.create_case("C1", "Case")
        database.log_activity("C1", "note", {"text": "first"})
        self.assertTrue(database.verify_audit_chain()["valid"])
        with self.assertRaises(Exception):
            with database._connect() as connection:
                connection.execute("UPDATE audit_log SET details_json='{}' WHERE seq=2")
        with self.assertRaises(Exception):
            with database._connect() as connection:
                connection.execute("DELETE FROM audit_log WHERE seq=1")

    def test_tampering_that_bypasses_triggers_is_detected(self):
        database.create_case("C1", "Case")
        database.log_activity("C1", "note", {"text": "original"})
        with database._connect() as connection:
            connection.execute("DROP TRIGGER audit_log_no_update")
            connection.execute("UPDATE audit_log SET details_json=? WHERE event_type='note'",
                               (json.dumps({"text": "forged"}),))
        status = database.verify_audit_chain()
        self.assertFalse(status["valid"])
        self.assertTrue(any("modified" in p for p in status["problems"]))

    def test_exported_bundle_verifies_with_standalone_tool(self):
        database.create_case("C1", "Case")
        database.log_activity("C1", "note", {"text": "हिन्दी नोट"})
        bundle_path = Path(self.tmp.name) / "bundle.json"
        key_path = Path(self.tmp.name) / "key.pem"
        bundle_path.write_text(json.dumps(database.export_audit_bundle()), encoding="utf-8")
        key_path.write_text(crypto.public_key_pem())
        tool = ROOT / "tools" / "verify_audit_bundle.py"
        ok = subprocess.run([sys.executable, str(tool), str(bundle_path), "--public-key", str(key_path)],
                            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["entries"][1]["actor"] = "someone-else@police.gov.in"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        bad = subprocess.run([sys.executable, str(tool), str(bundle_path), "--public-key", str(key_path)],
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)

    def test_actor_is_recorded(self):
        database.create_case("C1", "Case")
        with database.acting_as("si.sharma@police.gov.in"):
            database.log_activity("C1", "note", {})
        self.assertEqual(database.list_activity("C1")[-1]["actor"], "si.sharma@police.gov.in")


class ProvenanceTests(TempDB):
    def test_provenance_and_custody_recorded(self):
        database.create_case("C1", "Case")
        content = b"chat export"
        item = self.add("C1", "chat.txt", content,
                        {**PROVENANCE, "acquisition_sha256": hashlib.sha256(content).hexdigest()})
        provenance = database.get_provenance(item["evidence_id"])
        self.assertEqual(provenance["hash_verified"], 1)
        actions = [e["action"] for e in database.list_custody(item["evidence_id"])]
        self.assertEqual(actions, ["acquired", "received_into_vault"])
        database.add_custody_event("C1", item["evidence_id"], "transferred", "SI Test", "FSL Lab")
        self.assertEqual(database.list_custody(item["evidence_id"])[-1]["to_party"], "FSL Lab")
        with self.assertRaises(Exception):
            with database._connect() as connection:
                connection.execute("UPDATE evidence_provenance SET legal_authority='x'")

    def test_acquisition_hash_mismatch_is_rejected(self):
        database.create_case("C1", "Case")
        item = process_upload(Upload("chat.txt", b"altered copy"), "C1")
        with self.assertRaisesRegex(ValueError, "does not match"):
            database.save_evidence("C1", item, b"altered copy", {**PROVENANCE, "acquisition_sha256": "a" * 64})
        self.assertEqual(database.list_evidence("C1"), [])
        self.assertIn("evidence_rejected_hash_mismatch",
                      [e["event_type"] for e in database.list_activity("C1")])

    def test_required_fields_enforced(self):
        database.create_case("C1", "Case")
        item = process_upload(Upload("x.txt", b"x"), "C1")
        with self.assertRaisesRegex(ValueError, "legal_authority"):
            database.save_evidence("C1", item, b"x", {**PROVENANCE, "legal_authority": ""})


class AccessControlTests(TempDB):
    def _approved(self, email, admin):
        auth.register_officer(email, "OfficerPass1", "Officer", "B-" + email[:3], "Cyber")
        user = auth.get_user_by_email(email)
        auth.set_user_status(admin, user["user_id"], "approved")
        return auth.get_user(user["user_id"])

    def test_case_membership_limits_access(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        admin = auth.get_user_by_email("admin@police.gov.in")
        lead = self._approved("lead@police.gov.in", admin)
        viewer = self._approved("view@police.gov.in", admin)
        outsider = self._approved("out@police.gov.in", admin)
        database.create_case("C1", "Case", created_by_user_id=lead["user_id"])
        database.set_case_member("C1", viewer["user_id"], "viewer")

        self.assertEqual([c["case_id"] for c in access.accessible_cases(lead)], ["C1"])
        self.assertEqual(access.accessible_cases(outsider), [])
        self.assertTrue(access.can(viewer, "C1", "view"))
        self.assertFalse(access.can(viewer, "C1", "edit"))
        self.assertTrue(access.can(lead, "C1", "manage"))
        self.assertTrue(access.can(admin, "C1", "manage"))
        with self.assertRaises(access.AccessDenied):
            access.require(outsider, "C1", "view")
        self.assertIn("access_denied", [e["event_type"] for e in database.list_activity("C1")])
        with self.assertRaisesRegex(ValueError, "lead"):
            database.remove_case_member("C1", lead["user_id"])


class ClaimVerificationTests(unittest.TestCase):
    SOURCES = [{"evidence_id": "EV-REAL", "filename": "mail.txt",
                "snippet": "From: alice@corp.test 2024-03-01 21:14 UTC. Alice copied payroll.xlsx to USB drive E:."}]

    def test_fabricated_claim_with_real_citation_is_removed(self):
        answer = ("Alice copied payroll.xlsx to a USB drive [EV-REAL]. "
                  "Bob deleted the server logs at 23:50 [EV-REAL].")
        text, report = verify_generated_text(answer, self.SOURCES)
        self.assertIn("Alice copied payroll.xlsx", text)
        self.assertNotIn("Bob deleted", text)
        self.assertEqual(report["supported"], 1)
        self.assertEqual(report["unsupported"], 1)

    def test_claim_citing_wrong_passage_is_removed(self):
        sources = self.SOURCES + [{"evidence_id": "EV-OTHER", "filename": "x", "snippet": "Weather was clear."}]
        report = verify_answer("Alice copied payroll.xlsx [EV-OTHER].", sources)
        self.assertEqual(report["supported"], 0)

    def test_all_unsupported_withholds_output(self):
        text, report = verify_generated_text("Charlie wired 50000 rupees [EV-REAL].", self.SOURCES)
        self.assertIn("did not present", text)
        self.assertTrue(report["rejected"])


class StorageAndSearchTests(TempDB):
    def test_reports_persist(self):
        database.create_case("C1", "Case")
        report_id = database.save_report("C1", "ai_draft", "Draft", "Body [EV-1]", "English", ["EV-1"],
                                         {"supported": 1})
        saved = database.list_reports("C1")[0]
        self.assertEqual(saved["report_id"], report_id)
        self.assertEqual(saved["sha256"], hashlib.sha256(b"Body [EV-1]").hexdigest())
        self.assertIn("report_saved", [e["event_type"] for e in database.list_activity("C1")])

    def test_large_case_uses_fts_index(self):
        database.create_case("C1", "Case")
        self.add("C1", "a.txt", "routine entry. ".encode() * 400 + b"suspicious crypto wallet bc1qxyz transfer")
        self.add("C1", "b.txt", "हवाला लेनदेन की जानकारी पुलिस थाना को दी गई".encode())
        with patch.object(search_engine, "SCAN_LIMIT", 1):
            evidence = database.list_evidence("C1")
            results = search_engine.search_evidence("crypto wallet", evidence, top_k=3)
            hindi = search_engine.search_evidence("हवाला लेनदेन", evidence, top_k=1)
        self.assertIn("bc1qxyz", results[0]["snippet"])
        self.assertIn("indexed", results[0]["retrieval_mode"])
        self.assertIn("हवाला", hindi[0]["snippet"])

    def test_background_ingest_job(self):
        database.create_case("C1", "Case")
        content = b"login from 10.0.0.5 at 2024-01-01T10:00:00Z"
        job_id = jobs.enqueue("ingest_upload", "C1", {
            "staging_token": jobs.stage_upload(content), "filename": "auth.log",
            "provenance": PROVENANCE, "label": "auth.log"}, "si@police.gov.in")
        self.assertTrue(jobs.run_pending_once())
        job = [j for j in jobs.list_jobs("C1") if j["job_id"] == job_id][0]
        self.assertEqual(job["status"], "done", job["error"])
        self.assertEqual(len(database.list_evidence("C1")), 1)
        self.assertEqual(list(jobs.staging_dir().iterdir()), [])
        ingest = [e for e in database.list_activity("C1") if e["event_type"] == "evidence_ingested"][0]
        self.assertEqual(ingest["actor"], "si@police.gov.in")

    def test_server_import_outside_allowed_dirs_is_refused(self):
        database.create_case("C1", "Case")
        jobs.enqueue("ingest_path", "C1", {"path": "/etc/passwd", "filename": "passwd"}, "si@police.gov.in")
        jobs.run_pending_once()
        self.assertEqual(jobs.list_jobs("C1")[0]["status"], "failed")

    def test_agent_uses_tools_and_answer_is_verified(self):
        database.create_case("C1", "Case")
        item = self.add("C1", "events.csv", b"time,user,action\n2024-01-01T10:00:00Z,alice,usb_copy\n")
        evidence = database.list_evidence("C1")
        replies = iter([
            {"content": "", "tool_calls": [{"function": {"name": "filter_records", "arguments": {
                "evidence_id": item["evidence_id"], "field": "user", "value": "alice"}}}]},
            {"content": f"Alice performed usb_copy [{item['evidence_id']}]. "
                        f"Alice also emailed the CFO [{item['evidence_id']}]."},
        ])
        outcome = run_agent("What did alice do?", "C1", evidence, search_engine.search_evidence,
                            chat=lambda messages, tools=None: next(replies))
        self.assertEqual(outcome["steps"][0]["tool"], "filter_records")
        self.assertIn("usb_copy", outcome["answer"])
        self.assertNotIn("emailed the CFO", outcome["answer"])
        self.assertEqual(outcome["verification"]["unsupported"], 1)


class HindiPdfTests(unittest.TestCase):
    def test_hindi_pdf_uses_shaped_text(self):
        from modules.report_generator import make_pdf
        import pymupdf
        pdf = make_pdf("केस डायरी", "पुलिस थाना साक्ष्य क्षेत्र प्रविष्टि", "हिन्दी")
        fonts = [font[3] for font in pymupdf.open(stream=pdf).load_page(0).get_fonts()]
        self.assertTrue(any("Devanagari" in name for name in fonts), fonts)


if __name__ == "__main__":
    unittest.main()
