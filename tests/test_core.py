import hashlib
import tempfile
import unittest
from array import array
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from modules import auth, database
from modules.anomaly_engine import analyze_structured_evidence
from modules.evidence_processor import process_upload
from modules.i18n import tr
from modules.llm_engine import enforce_valid_evidence_citations, resolve_followup_query
from modules.relationship_engine import build_relationship_graph, supporting_records
from modules.report_generator import make_case_diary, make_pdf
from modules.search_engine import search_evidence
from modules.search_engine import make_chunks
from streamlit.testing.v1 import AppTest


class MemoryUpload:
    def __init__(self, name, content):
        self.name = name
        self._content = content

    def getvalue(self):
        return self._content


def make_png(width=12, height=8):
    buffer = BytesIO()
    Image.new("RGB", (width, height), (40, 80, 120)).save(buffer, format="PNG")
    return buffer.getvalue()


class EvidenceProcessingTests(unittest.TestCase):
    def test_hindi_core_ui_translation(self):
        self.assertEqual(tr("Search", "हिन्दी"), "खोजें")

    def test_hash_and_text_extraction(self):
        content = b"From: analyst@example.test\nSubject: Access review"
        item = process_upload(MemoryUpload("mail.txt", content), "CASE-TEST")
        self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
        self.assertIn("Subject: Access review", item["text"])
        self.assertNotEqual(item["evidence_id"], "EV-" + item["sha256"][:10].upper())

    def test_image_upload_records_metadata_without_ocr(self):
        item = process_upload(MemoryUpload("scene.png", make_png()), "CASE-TEST")
        self.assertEqual(item["text"], "")
        self.assertEqual(item["extraction_status"], "Image stored (no OCR)")
        self.assertEqual(item["metadata"]["width"], 12)
        self.assertEqual(item["metadata"]["height"], 8)
        self.assertEqual(item["metadata"]["format"], "PNG")

    def test_invalid_image_upload_is_rejected(self):
        with self.assertRaises(ValueError):
            process_upload(MemoryUpload("fake.png", b"not an image"), "CASE-TEST")

    def test_search_returns_source_reference(self):
        evidence = [{
            "evidence_id": "EV-TEST",
            "filename": "mail.txt",
            "text": "The user copied confidential project files to an external drive.",
        }]
        results = search_evidence("confidential project files", evidence, top_k=3)
        self.assertTrue(results)
        self.assertEqual(results[0]["evidence_id"], "EV-TEST")


class PersistenceTests(unittest.TestCase):
    def test_case_evidence_chat_and_integrity_persist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-TEST", "Test case")
                database.create_case("CASE-OTHER", "Other case")
                content = b"A small evidence artifact"
                item = process_upload(MemoryUpload("artifact.txt", content), "CASE-TEST")
                self.assertTrue(database.save_evidence("CASE-TEST", item, content))
                self.assertFalse(database.save_evidence("CASE-TEST", item, content))
                stored = database.list_evidence("CASE-TEST")
                self.assertEqual(len(stored), 1)
                self.assertEqual(stored[0]["text"], item["text"])
                self.assertEqual(database.verify_original(item["evidence_id"], "CASE-TEST")[0], True)
                chunks = make_chunks(item["text"])
                database.replace_evidence_chunks(
                    "CASE-TEST", item["evidence_id"], "test-model", chunks,
                    [array("f", [1.0, 0.0]) for _ in chunks],
                )
                self.assertEqual(database.count_evidence_chunks("CASE-TEST", "test-model"), len(chunks))
                other_case_item = process_upload(MemoryUpload("artifact.txt", content), "CASE-OTHER")
                self.assertNotEqual(item["evidence_id"], other_case_item["evidence_id"])
                self.assertTrue(database.save_evidence("CASE-OTHER", other_case_item, content))
                self.assertEqual(len(database.list_evidence("CASE-OTHER")), 1)
                database.save_analysis_result("CASE-TEST", "anomaly", {"flagged": []})
                self.assertEqual(database.load_analysis_result("CASE-TEST", "anomaly"), {"flagged": []})
                database.save_leads("CASE-TEST", [{
                    "lead_id": "LEAD-1", "type": "review", "statement": "Review source", 
                    "basis": "Rule", "supporting_evidence": [item["evidence_id"]],
                    "suggested_follow_up": "Inspect source", "status": "Unreviewed",
                }])
                self.assertEqual(database.list_leads("CASE-TEST")[0]["lead_id"], "LEAD-1")
                Path(stored[0]["original_path"]).write_bytes(b"changed")
                self.assertFalse(database.verify_original(item["evidence_id"], "CASE-TEST")[0])
                database.save_chat_message("CASE-TEST", "user", "What happened?")
                database.save_chat_message(
                    "CASE-TEST", "assistant", "A source-based answer.",
                    retrieval_query="What happened?",
                )
                messages = database.list_chat_messages("CASE-TEST")
                self.assertEqual(messages[0]["content"], "What happened?")
                self.assertEqual(messages[1]["retrieval_query"], "What happened?")
                database.clear_chat("CASE-TEST")
                self.assertEqual(database.list_chat_messages("CASE-TEST"), [])

    def test_image_metadata_and_original_persist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-IMG", "Image case")
                raw = make_png(20, 10)
                item = process_upload(MemoryUpload("photo.png", raw), "CASE-IMG")
                self.assertTrue(database.save_evidence("CASE-IMG", item, raw))
                stored = database.list_evidence("CASE-IMG")[0]
                self.assertEqual(stored["metadata"], item["metadata"])
                self.assertEqual(stored["extraction_status"], "Image stored (no OCR)")
                self.assertTrue(database.verify_original(item["evidence_id"], "CASE-IMG")[0])

    def test_evidence_deletion_removes_derived_data_but_keeps_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-DEL", "Delete case")
                content = b"record to delete"
                item = process_upload(MemoryUpload("record.txt", content), "CASE-DEL")
                self.assertTrue(database.save_evidence("CASE-DEL", item, content))
                chunks = make_chunks(item["text"])
                database.replace_evidence_chunks(
                    "CASE-DEL", item["evidence_id"], "test-model", chunks,
                    [array("f", [1.0, 0.0]) for _ in chunks],
                )
                database.save_analysis_result("CASE-DEL", "anomaly", {"flagged": []})
                database.save_leads("CASE-DEL", [{
                    "lead_id": "LEAD-DEL", "type": "review", "statement": "Review source",
                    "basis": "Rule", "supporting_evidence": [item["evidence_id"]],
                    "suggested_follow_up": "Inspect source",
                    "status": "Closed - no further action",
                }])
                database.save_chat_message("CASE-DEL", "user", "Still here?")
                original_path = Path(database.list_evidence("CASE-DEL")[0]["original_path"])

                result = database.delete_evidence("CASE-DEL", item["evidence_id"])

                self.assertTrue(result["original_removed"])
                self.assertFalse(original_path.exists())
                self.assertEqual(database.list_evidence("CASE-DEL"), [])
                self.assertEqual(database.count_evidence_chunks("CASE-DEL", "test-model"), 0)
                self.assertIsNone(database.load_analysis_result("CASE-DEL", "anomaly"))
                self.assertEqual(database.list_leads("CASE-DEL")[0]["status"], "Needs refresh")
                self.assertEqual(database.list_chat_messages("CASE-DEL")[0]["content"], "Still here?")
                events = [event["event_type"] for event in database.list_activity("CASE-DEL")]
                self.assertIn("evidence_deleted", events)
                self.assertIn("case_created", events)
                self.assertEqual([case["case_id"] for case in database.list_cases()], ["CASE-DEL"])

    def test_evidence_deletion_keeps_shared_original_file(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-A", "A")
                database.create_case("CASE-B", "B")
                content = b"shared original bytes"
                first_item = process_upload(MemoryUpload("a.txt", content), "CASE-A")
                second_item = process_upload(MemoryUpload("b.txt", content), "CASE-B")
                database.save_evidence("CASE-A", first_item, content)
                database.save_evidence("CASE-B", second_item, content)
                first = database.list_evidence("CASE-A")[0]
                shared_path = first["original_path"]

                connection = sqlite3.connect(database.DATABASE_PATH)
                connection.execute(
                    "UPDATE evidence SET original_path=? WHERE evidence_id=?",
                    (shared_path, second_item["evidence_id"]),
                )
                connection.commit()
                connection.close()

                result = database.delete_evidence("CASE-A", first_item["evidence_id"])

                self.assertFalse(result["original_removed"])
                self.assertTrue(Path(shared_path).exists())
                self.assertEqual(len(database.list_evidence("CASE-B")), 1)

    def test_case_deletion_removes_only_target_case_and_blocks_last_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-A", "A")
                database.create_case("CASE-B", "B")
                first_content = b"first case evidence"
                second_content = b"second case evidence"
                first_item = process_upload(MemoryUpload("a.txt", first_content), "CASE-A")
                second_item = process_upload(MemoryUpload("b.txt", second_content), "CASE-B")
                database.save_evidence("CASE-A", first_item, first_content)
                database.save_evidence("CASE-B", second_item, second_content)
                database.save_chat_message("CASE-A", "user", "remove me")
                first_path = Path(database.list_evidence("CASE-A")[0]["original_path"])
                second_path = Path(database.list_evidence("CASE-B")[0]["original_path"])

                result = database.delete_case("CASE-A")

                self.assertEqual(result["case_id"], "CASE-A")
                self.assertEqual(result["files_removed"], 1)
                self.assertFalse(first_path.exists())
                self.assertTrue(second_path.exists())
                self.assertEqual([case["case_id"] for case in database.list_cases()], ["CASE-B"])
                self.assertEqual(len(database.list_evidence("CASE-B")), 1)
                self.assertEqual(database.list_chat_messages("CASE-A"), [])
                self.assertEqual(database.list_activity("CASE-A"), [])
                with self.assertRaises(ValueError):
                    database.delete_case("CASE-B")

    def test_legacy_paths_and_per_case_originals_are_handled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-A", "A")
                database.create_case("CASE-B", "B")
                content = b"shared original bytes"
                first = process_upload(MemoryUpload("a.txt", content), "CASE-A")
                second = process_upload(MemoryUpload("b.txt", content), "CASE-B")
                self.assertNotEqual(first["evidence_id"], second["evidence_id"])
                self.assertTrue(database.save_evidence("CASE-A", first, content))
                self.assertTrue(database.save_evidence("CASE-B", second, content))
                paths = {
                    Path(database.list_evidence(case)[0]["original_path"])
                    for case in ("CASE-A", "CASE-B")
                }
                self.assertEqual(len(paths), 2)

                legacy = "data\\evidence\\" + first["evidence_id"] + ".bin"
                with database._connect() as connection:
                    connection.execute(
                        "UPDATE evidence SET original_path=? WHERE evidence_id=?",
                        (legacy, first["evidence_id"]),
                    )
                self.assertTrue(Path(database.list_evidence("CASE-A")[0]["original_path"]).is_file())
                database.initialize_database()
                with database._connect() as connection:
                    stored_path = connection.execute(
                        "SELECT original_path FROM evidence WHERE evidence_id=?",
                        (first["evidence_id"],),
                    ).fetchone()["original_path"]
                self.assertNotIn("\\", stored_path)
                self.assertTrue(database.verify_original(first["evidence_id"], "CASE-A")[0])

    def test_lead_status_survives_refresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-A", "A")
                lead = {
                    "lead_id": "LEAD-TEST",
                    "type": "review",
                    "statement": "Review source",
                    "basis": "Rule",
                    "supporting_evidence": [],
                    "suggested_follow_up": "Inspect source",
                    "status": "Actioned",
                }
                database.save_leads("CASE-A", [lead])
                self.assertEqual(database.list_leads("CASE-A")[0]["status"], "Actioned")
                database.save_leads("CASE-A", [{**lead, "status": "Unreviewed"}])
                self.assertEqual(database.list_leads("CASE-A")[0]["status"], "Actioned")


class AnalysisTests(unittest.TestCase):

    def test_uncited_or_fabricated_model_claim_is_not_shown_as_a_finding(self):
        sources = [{"evidence_id": "EV-REAL", "filename": "record.txt"}]
        uncited = enforce_valid_evidence_citations("Alice accessed the file.", sources)
        fabricated = enforce_valid_evidence_citations("Alice accessed the file [EV-FAKE].", sources)
        cited = enforce_valid_evidence_citations("Alice is named in the record [EV-REAL].", sources)
        self.assertIn("did not present", uncited)
        self.assertIn("did not present", fabricated)
        self.assertEqual(cited, "Alice is named in the record [EV-REAL].")

    def test_refusal_without_citations_is_allowed(self):
        sources = [{"evidence_id": "EV-REAL", "filename": "record.txt"}]
        answer = "INSUFFICIENT EVIDENCE: no relevant records were retrieved."
        self.assertEqual(enforce_valid_evidence_citations(answer, sources), answer)

    def test_relationship_truncation_counts_all_omitted_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.csv"
            path.write_text(
                "user,activity\nalice,login\nbob,login\ncarol,login\ndan,login\neve,login\n",
                encoding="utf-8",
            )
            item = {
                "evidence_id": "EV-CSV",
                "filename": "events.csv",
                "file_type": "csv",
                "text": "",
                "original_path": str(path),
            }
            with patch("modules.relationship_engine.MAX_RECORDS", 2):
                _, _, stats = build_relationship_graph([item])
            self.assertEqual(stats["records"], 2)
            self.assertEqual(stats["truncated"], 3)

    def test_anomaly_reports_physical_csv_line_for_multiline_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "multiline.csv"
            path.write_text(
                'timestamp,user,activity,note\n'
                '"2025-01-01T10:00:00+00:00",analyst,login,"first\nsecond"\n'
                '"2025-01-01T02:00:00+00:00",analyst,rare_download,note\n',
                encoding="utf-8",
            )
            flagged, _ = analyze_structured_evidence([{
                "evidence_id": "EV-CSV",
                "filename": "multiline.csv",
                "file_type": "csv",
                "original_path": str(path),
            }])
            self.assertIn(4, [row["row_number"] for row in flagged])

    def test_naive_timestamps_do_not_create_burst_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "naive.csv"
            rows = ["timestamp,user,activity"]
            rows.extend(
                f"2025-01-01T10:{minute:02d}:00,analyst,login"
                for minute in range(5)
            )
            path.write_text("\n".join(rows), encoding="utf-8")
            flagged, _ = analyze_structured_evidence([{
                "evidence_id": "EV-CSV",
                "filename": "naive.csv",
                "file_type": "csv",
                "original_path": str(path),
            }])
            self.assertEqual(flagged, [])

    def test_followup_query_uses_local_chat_rewrite(self):
        from unittest.mock import patch
        from unittest.mock import Mock

        response = Mock()
        response.json.return_value = {"message": {"content": "What files did Alice access?"}}
        history = [
            {"role": "user", "content": "Who sent the email?"},
            {"role": "assistant", "content": "The email lists Alice as the sender."},
        ]
        with patch("modules.llm_engine.requests.post", return_value=response):
            rewritten = resolve_followup_query("What did the sender access?", history)
        self.assertEqual(rewritten, "What files did Alice access?")

    def test_anomaly_flag_includes_original_csv_row(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.csv"
            rows = ["timestamp,user,activity"]
            rows.extend(
                f"2025-01-01T10:{minute:02d}:00+00:00,analyst,login"
                for minute in range(9)
            )
            rows.append("2025-01-01T02:00:00+00:00,analyst,rare_download")
            path.write_text("\n".join(rows), encoding="utf-8")
            flagged, summaries = analyze_structured_evidence([{
                "evidence_id": "EV-CSV",
                "filename": "events.csv",
                "file_type": "csv",
                "original_path": str(path),
            }])
        target = next(row for row in flagged if row["row_number"] == 11)
        self.assertTrue(target["reasons"])
        self.assertEqual(summaries[0]["records_analyzed"], 10)

    def test_relationship_graph_links_reused_identifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.csv"
            second = Path(temporary) / "second.csv"
            first.write_text("user,email\nalice,alice@example.test\n", encoding="utf-8")
            second.write_text("actor,email\nalice,alice@example.test\n", encoding="utf-8")
            catalog = [
                {"evidence_id": "EV-1", "filename": "first.csv", "file_type": "csv", "text": "", "original_path": str(first)},
                {"evidence_id": "EV-2", "filename": "second.csv", "file_type": "csv", "text": "", "original_path": str(second)},
            ]
            graph_html, records, stats = build_relationship_graph(catalog)
        self.assertIn("vis-network", graph_html)
        self.assertEqual(stats["records"], 2)
        matches = supporting_records(records, "alice@example.test")
        self.assertEqual(len(matches), 2)

    def test_report_pdf_is_created(self):
        diary = make_case_diary("CASE-1", "Demo", [])
        pdf = make_pdf("Demo report", diary)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_semantic_and_keyword_results_are_combined_when_indexed(self):
        import numpy as np
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(database, "PROJECT_ROOT", root),
                patch.object(database, "DATA_DIR", root / "data"),
                patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
                patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
            ):
                database.initialize_database()
                database.create_case("CASE-SEM", "Semantic test")
                content = b"A confidential memo about unusual financial transfers."
                item = process_upload(MemoryUpload("memo.txt", content), "CASE-SEM")
                database.save_evidence("CASE-SEM", item, content)
                chunks = make_chunks(item["text"])
                database.replace_evidence_chunks(
                    "CASE-SEM", item["evidence_id"], "embeddinggemma", chunks,
                    [array("f", [1.0, 0.0]) for _ in chunks],
                )
                with patch("modules.embedding_engine.embed_texts", return_value=[np.asarray([1.0, 0.0], dtype=np.float32)]):
                    results = search_evidence(
                        "wire transfer", database.list_evidence("CASE-SEM"), top_k=1
                    )
        self.assertTrue(results)
        self.assertEqual(results[0]["retrieval_mode"], "Hybrid semantic + TF-IDF")


APP_PATH = str(Path(__file__).resolve().parents[1] / "app.py")


class _TempDatabaseMixin:
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        self._patches = [
            patch.object(database, "PROJECT_ROOT", root),
            patch.object(database, "DATA_DIR", root / "data"),
            patch.object(database, "EVIDENCE_DIR", root / "data" / "evidence"),
            patch.object(database, "DATABASE_PATH", root / "data" / "test.db"),
        ]
        for item in self._patches:
            item.start()
        database.initialize_database()
        auth.initialize_auth()

    def tearDown(self):
        for item in reversed(self._patches):
            item.stop()
        self._temporary.cleanup()


class AuthTests(_TempDatabaseMixin, unittest.TestCase):
    def test_password_hash_round_trip(self):
        stored = auth.hash_password("Secret12345")
        self.assertTrue(auth.verify_password("Secret12345", stored))
        self.assertFalse(auth.verify_password("wrong-pass-1", stored))

    def test_pending_officer_cannot_sign_in_until_admin_approves(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        auth.register_officer("officer@police.gov.in", "OfficerPass1", "A Officer", "B-101", "Cyber")
        with self.assertRaisesRegex(auth.AuthError, "approval"):
            auth.authenticate("officer@police.gov.in", "OfficerPass1")

        admin = auth.verify_token(auth.authenticate("admin@police.gov.in", "AdminPass123"))
        officer_id = auth.list_users("pending")[0]["user_id"]
        auth.set_user_status(admin, officer_id, "approved")
        token = auth.authenticate("officer@police.gov.in", "OfficerPass1")
        self.assertEqual(auth.verify_token(token)["role"], "officer")

        # Disabling revokes the already-issued token immediately.
        auth.set_user_status(admin, officer_id, "disabled")
        self.assertIsNone(auth.verify_token(token))

    def test_officer_cannot_use_admin_actions(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        auth.register_officer("officer@police.gov.in", "OfficerPass1", "A Officer", "B-101", "Cyber")
        admin = auth.verify_token(auth.authenticate("admin@police.gov.in", "AdminPass123"))
        officer_id = auth.list_users("pending")[0]["user_id"]
        auth.set_user_status(admin, officer_id, "approved")
        officer = auth.verify_token(auth.authenticate("officer@police.gov.in", "OfficerPass1"))
        with self.assertRaises(auth.AuthError):
            auth.set_user_role(officer, officer_id, "admin")

    def test_tampered_or_foreign_token_is_rejected(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        token = auth.authenticate("admin@police.gov.in", "AdminPass123")
        self.assertIsNone(auth.verify_token(token[:-2] + "xx"))
        import jwt as pyjwt
        forged = pyjwt.encode({"sub": "x", "role": "admin", "iss": "trace-ai", "exp": 9999999999,
                               "iat": 0}, "not-the-real-secret-" + "x" * 32, algorithm="HS256")
        self.assertIsNone(auth.verify_token(forged))

    def test_account_locks_after_repeated_failures(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(auth.AuthError):
                auth.authenticate("admin@police.gov.in", "wrong-pass-1")
        with self.assertRaisesRegex(auth.AuthError, "Too many"):
            auth.authenticate("admin@police.gov.in", "AdminPass123")


class AppIntegrationTests(_TempDatabaseMixin, unittest.TestCase):
    def _signed_in_app(self):
        auth.create_admin("admin@police.gov.in", "AdminPass123", "Admin")
        app = AppTest.from_file(APP_PATH, default_timeout=30)
        app.session_state["auth_token"] = auth.authenticate("admin@police.gov.in", "AdminPass123")
        return app.run()

    def test_app_requires_login(self):
        app = AppTest.from_file(APP_PATH, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0, [exception.message for exception in app.exception])
        self.assertIn("Sign in", [button.label for button in app.button])
        self.assertNotIn("Delete this case", [button.label for button in app.button])

    def test_streamlit_app_starts_without_script_exceptions(self):
        app = self._signed_in_app()
        self.assertEqual(len(app.exception), 0, [exception.message for exception in app.exception])

    def test_streamlit_uploader_accepts_image_evidence(self):
        app = self._signed_in_app()
        uploader = app.file_uploader(key="uploads_CASE-001")
        self.assertTrue({".png", ".jpg", ".jpeg", ".webp"}.issubset(set(uploader.allowed_type)))
        self.assertEqual(len(app.exception), 0, [exception.message for exception in app.exception])

    def test_streamlit_delete_controls_are_available(self):
        database.ensure_default_case()
        upload = MemoryUpload("note.txt", b"Suspect phone 9876543210 seen near tower 7.")
        database.save_evidence("CASE-001", process_upload(upload, "CASE-001"), upload.getvalue())
        app = self._signed_in_app()
        labels = [button.label for button in app.button]
        self.assertIn("Delete this case", labels)
        self.assertIn("Delete evidence", labels)
        self.assertEqual(len(app.exception), 0, [exception.message for exception in app.exception])

    def test_streamlit_app_renders_in_hindi(self):
        app = self._signed_in_app()
        app.selectbox(key="interface_language").set_value("हिन्दी").run()
        self.assertEqual(len(app.exception), 0, [exception.message for exception in app.exception])


if __name__ == "__main__":
    unittest.main()
