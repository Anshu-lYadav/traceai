# How TRACE AI's limitations were solved

This document explains how each of the 11 limitations was fixed: the method, the exact steps in the code, and how to check that it works. The high-risk security limitations come first, because they were fixed first.

**Before you start:** all commands run from the project folder with the project's virtual environment (`.venv/bin/python`).

**Libraries added:**

```bash
pip install cryptography sqlcipher3-binary rfc3161ng pyasn1 faiss-cpu \
            python-evtx dpkt pytsk3 libewf-python rapidocr-onnxruntime pytesseract \
            charset-normalizer volatility3
```

**To check everything at once:**

```bash
python -m unittest discover -s tests      # 76 tests
```

---

## 1. Unencrypted at rest

**Problem.** `data/trace_ai.db` and the uploaded originals (`data/evidence/*.bin`) were plain files. Anyone who copied the folder could read them.

**Method.** Encrypt both, and keep the keys outside the `data/` folder.

**Steps:**

1. **Create a key module** ([modules/crypto.py](../modules/crypto.py)).
   - On first use it creates a random 32-byte master key in `~/.config/trace_ai/master.key` with file permission `0600`.
   - It can be overridden with `TRACE_KEY_DIR`, or with `TRACE_MASTER_KEY` (base64).
   - Separate sub-keys are derived from the master key with HKDF-SHA256: one for the database and one per evidence file.
2. **Encrypt the database with SQLCipher.**
   - In [modules/database.py](../modules/database.py), `import sqlite3` is replaced by `from sqlcipher3 import dbapi2 as sqlite3`.
   - Every connection first runs `PRAGMA key = "x'<256-bit key>'"` (`_apply_key`).
   - If SQLCipher isn't installed, the app still runs and shows a warning that the database is not encrypted (`DB_ENCRYPTED`).
3. **Encrypt evidence files with AES-256-GCM in 1 MB chunks** (`encrypt_stream`, `decrypt_iter`).
   - **File header:** `TRACEENC1` + chunk size + a random 32-byte salt. The salt gives each file its own key.
   - **Each chunk:** a 12-byte random nonce, then the ciphertext and a 16-byte authentication tag.
   - **Extra authenticated data per chunk:** header + chunk number + an "is last chunk" flag. This means chunks cannot be reordered, removed or appended without detection.
   - **Safe write:** the file is written to `*.part` first and then renamed, so a crash never leaves a half-written file under its final name.
   - **Large files:** because it works chunk by chunk, it streams multi-GB disk images without loading them into memory.
4. **Store originals as `EV-xxxx.enc`.**
   - `save_evidence` / `save_evidence_from_path` encrypt the file and check that the SHA-256 of the plaintext equals the hash computed at upload.
   - `read_original` decrypts. `verify_original` decrypts and recomputes the hash; if decryption fails authentication, the file has been tampered with.
5. **Migrate old data automatically** (`_migrate_plaintext_database`, `_encrypt_legacy_originals`).
   - On startup, a database file that starts with `SQLite format 3` is plaintext. It is exported to an encrypted copy with SQLCipher's `sqlcipher_export()`.
   - Row counts are compared table by table before the copy is swapped in.
   - Old `.bin` originals are encrypted and re-hashed.
   - The plaintext copies are moved to `data/pre_encryption_backup/` for the operator to delete, not deleted automatically.

**Check:** `tests/test_security.py`, class `EncryptionTests`:
- the database header is no longer plaintext and a known secret string doesn't appear in the file;
- flipping one byte makes verification fail;
- a truncated file is detected;
- plaintext migration works.

---

## 2. Audit logs that wouldn't hold up in court

**Problem.** `activity_log` held ordinary SQLite rows. They could be edited or deleted, nothing was signed, and there was no trusted time.

**Method.** One append-only log, hash-chained like a blockchain, with every entry signed, SQL triggers against edits, and optional RFC 3161 timestamps.

**Steps:**

1. **New tables** in `database.py`:
   - `audit_log`: `seq`, `case_id`, `actor`, `event_type`, `details_json`, `created_at`, `prev_hash`, `entry_hash`, `signature`, `key_id`.
   - `audit_head`: the current sequence number and last hash.
2. **Writing an entry** (`_append_audit`):
   1. Lock the chain by updating `audit_head`. This takes SQLite's write lock, so two writers can never extend the chain from the same point.
   2. `entry_hash = SHA-256(canonical JSON of {seq, case_id, actor, event_type, details, created_at, legacy, prev_hash})`, with sorted keys, no spaces and UTF-8.
   3. `signature = Ed25519(entry_hash)`, using the private key `~/.config/trace_ai/audit_signing.key`.
   4. Insert the row and move `audit_head` forward.
3. **Record who did it.**
   - `database.set_actor(email)` is called on every page run for the signed-in user.
   - Background jobs use `acting_as(email)` for the officer who started the job.
   - Login and admin events (`auth._audit`) go into the same chain.
4. **Block edits:** `CREATE TRIGGER … BEFORE UPDATE/DELETE … RAISE(ABORT)` on `audit_log`, `audit_anchors`, `custody_events` and `evidence_provenance`.
5. **Verify** (`verify_audit_chain`):
   - recompute every hash and check every signature;
   - check sequence gaps and the previous-hash links;
   - compare the head with the last entry;
   - compare with any timestamp anchors.

   A row changed directly, bypassing the triggers, shows up as "content was modified".
6. **Keep the log when a case is deleted.** `delete_case` now marks the case deleted (`deleted_at`) and removes the evidence, but the audit rows stay.
7. **Import old log entries once** (`_import_legacy_logs`). They are marked `legacy`, plus one final entry that says the older content is only protected from the import time onward.
8. **Trusted time** ([modules/timestamping.py](../modules/timestamping.py)):
   - `anchor_audit_head()` sends only the head hash to the timestamp authority (TSA) set in `TRACE_TSA_URL`, using `rfc3161ng`.
   - The signed token is stored in `audit_anchors`.
   - An anchor proves the chain existed at that time and exposes any later truncation.
9. **Third-party check.**
   - `export_audit_bundle()` produces JSON containing the entries, the public key and the anchors. A case export contains only that case's entries.
   - [tools/verify_audit_bundle.py](../tools/verify_audit_bundle.py) re-checks the bundle with only `cryptography` installed. Use `--public-key` with the key from the Admin tab.
10. **UI:** the *Audit & Custody* tab has the verify button and the export. The Admin tab has the public key download, the anchor button and the full export.

**Check:** class `AuditChainTests`:
- triggers block UPDATE and DELETE;
- dropping a trigger and editing a row is detected;
- the standalone tool accepts a real bundle and rejects an edited one;
- the actor is recorded.

---

## 3. No provenance or chain of custody

**Problem.** The SHA-256 only showed that the copy hadn't changed after upload. It said nothing about where the evidence came from, who acquired it, or under what authority.

**Method.** Require acquisition details at upload, check the acquirer's hash, and record every hand-over as a signed event.

**Steps:**

1. **Table `evidence_provenance`**, write-once: source, device ID (IMEI/serial), acquired by, method, tool, acquisition time with time zone, legal authority (FIR / seizure memo / warrant), Section 63 BSA / 65B certificate reference, acquisition SHA-256, a hash-verified flag, and notes.
2. **Validation** (`_validate_provenance`):
   - the required fields must be filled;
   - the acquisition hash must be 64 hex characters;
   - `hash_verified` is 1 (match), 0 (mismatch) or empty (no hash given).
3. **Reject mismatches** (`_reject_hash_mismatch`). If the uploaded file's SHA-256 differs from the acquirer's hash, the file is not stored. A signed `evidence_rejected_hash_mismatch` event is written, and an error is shown.
4. **Table `custody_events`**, append-only.
   - Each event is also written into the signed audit chain.
   - Automatic events: `acquired`, `received_into_vault`, `removed_from_vault`, and `copied_for_analysis`. The last happens when an officer downloads a verified working copy, which is decrypted and re-hashed first.
   - Manual events: `transferred`, `examined`, `sealed`, `returned`, `correction`.
5. **UI** ([app.py](../app.py), Evidence Vault):
   - The upload form asks for the custody fields. Hashes can be pasted as `sha256sum` output.
   - A "Provenance & custody" tab shows each item's history.
   - Evidence without a record gets a warning and a "Record provenance" form.
6. **Custody register:** `make_custody_report` in [modules/report_generator.py](../modules/report_generator.py), downloadable from *Audit & Custody*.

**Check:** class `ProvenanceTests` (record plus custody history, mismatch rejected, required fields).

**Note:** the software records and checks the acquisition details. Whether the acquisition was lawful is still shown by the certificate and the examiner's testimony.

---

## 4. Flat multi-tenancy (every approved user could see and delete everything)

**Problem.** Being signed in was the only check. Every approved user could see and delete every case.

**Method.** Add membership per case, with roles, and check permissions on every action.

**Steps:**

1. **Table `case_members`** (`case_id`, `user_id`, `case_role`).
   - Roles are `viewer`, `investigator` and `lead`.
   - Whoever creates a case becomes its lead (`create_case(…, created_by_user_id=…)`).
2. **[modules/access.py](../modules/access.py):**

   | Permission | Who has it |
   |---|---|
   | `view` | viewer, investigator, lead |
   | `edit` | investigator, lead |
   | `manage` | lead |

   - Admins have every permission.
   - `accessible_cases(user)` returns only the user's cases (all cases for an admin).
   - `require()` raises `AccessDenied` and writes a signed `access_denied` event.
3. **In `app.py`:**
   - The case list comes from `accessible_cases`.
   - `can_edit` / `can_manage` hide or disable upload, chat, notes, delete and team management.
   - Destructive actions call `access.require(...)` again on the server before they run.
4. **"Case team" in the sidebar:** the lead or an admin adds an approved officer by email, changes roles, or removes members. A case cannot lose its last lead.
5. **AI tools** are tied to the single active case that passed the permission check, so the model cannot reach other cases.

**Check:** `AccessControlTests`. An outsider sees nothing, a viewer cannot edit, and leads and admins can manage. A rendered-app test also confirms that a viewer gets no upload, delete or chat controls.

---

## 5. Citation hallucinations

**Problem.** The guard only checked that some valid `[EV-…]` tag appeared, so a made-up claim with a real tag passed.

**Method.** Check each claim against the evidence it cites.

**Steps** ([modules/claim_verifier.py](../modules/claim_verifier.py)):

1. **Split the answer** into lines, then sentences. A citation that ends up alone after a full stop is attached back to its sentence.
2. **Skip what isn't a claim:** headings, plus refusal and limitation sentences such as "cannot be established" or "insufficient evidence".
3. **For each cited sentence:**
   1. **Real IDs:** every cited ID must be among the passages the model was actually given.
   2. **Specific details:** emails, IPs, URLs, numbers, dates and times, quoted text, IDs that contain digits, and capitalised names must appear in the cited passage, not in some other passage. Generic report words such as "Evidence" or "Conclusion" are ignored.
   3. **Key words:** at least half of the sentence's key words must appear in the cited passage. Words are matched on their first 5 letters, so word endings don't matter.
   4. **Cross-language claims:** if the claim is in Devanagari and the evidence isn't, only the identifiers are checked, and the result is marked partial.
   5. **Optional second check:** with `TRACE_LLM_CLAIM_CHECK=1`, the local model judges whether the passage states the claim. This check can only remove claims, never add them.
4. **Uncited sentences** that contain specific details (names, amounts, IPs) are removed too.
5. **Showing the result:** unsupported sentences are replaced with a "⚠️ Removed claim…" line. If no claim survives, the whole answer is withheld.
6. **Wiring:** `llm_engine.verify_generated_text()` returns the checked text and a report. The chat and the saved reports show "N verified · M removed", with a list of what was removed.

**Check:** `ClaimVerificationTests`. A fabricated claim with a real tag is removed, citing the wrong passage is caught, and an answer with no supported claim is withheld.

---

## 6. No OCR

**Method.** Try several OCR engines in order, and use OCR only on pages that have no text layer. (Built by a helper agent working in parallel.)

**Steps** ([modules/ocr.py](../modules/ocr.py), [modules/evidence_processor.py](../modules/evidence_processor.py)):

1. **`ocr_image_bytes()` tries engines in this order:**
   1. Tesseract, if the program is installed (`eng` + `hin`).
   2. RapidOCR (offline ONNX models, created once and cached).
   3. An Ollama vision model, if `TRACE_OCR_MODEL` is set.
2. **Prepare the image:** convert to RGB, correct the EXIF rotation, and shrink it if any side is over 4000 px.
3. **Scanned PDFs:** any page with fewer than 25 visible characters is rendered at 200 dpi with PyMuPDF and OCR'd, labelled `[Page N — OCR]`. At most 200 pages are OCR'd per PDF.
4. **Status:** the extraction status records which engine was used (for example "Text extracted (OCR: rapidocr)"). OCR'd text is indexed and searchable like any other text.

**Check:** `tests/test_extraction.py` OCRs a rendered PNG and an image-only PDF.

**To enable Hindi OCR:** `sudo apt install tesseract-ocr tesseract-ocr-hin`.

---

## 7. No forensic formats

**Method.** A parser per format in [modules/forensics.py](../modules/forensics.py). Each returns `{text, timeline, metadata, status}`.

| Format | Library | Output |
|---|---|---|
| EVTX (.evtx) | python-evtx | One line per record (EventID, time, computer, user, IP…), counts per event ID, timeline entries |
| PCAP / PCAPNG | dpkt + own pcap reader and TLS ClientHello parser | Flows, DNS queries and answers, HTTP host/path, TLS SNI, top talkers, timeline |
| E01 / Ex01 | pyewf (joins all segments) + pytsk3 | Partition table → each filesystem → file list with size, MAC times, `[DELETED]` flag, text of small text files, timeline |
| Raw .dd/.raw/.img/.001 | pytsk3 | Same as E01; the image is only read, never written |
| Memory .mem/.vmem/.lime/.dmp | volatility3 (as a separate process, with a time limit) | `windows.info`, `pslist`, `netscan` (Linux `pslist` as fallback). Otherwise a strings scan for IPs, URLs and emails |

**Steps:**

1. **Hash large files without loading them:** `process_path()` hashes in 4 MB blocks.
2. **Server import for very large images:** they can be imported from a folder on the server (`TRACE_IMPORT_DIRS`, default `data/import`). The job refuses any path outside the allowed folders.
3. **Size caps:** text up to 5,000,000 characters and timeline up to 50,000 events, with a warning when cut. Damaged input gives partial results rather than a crash.
4. **Timeline:** every parser's events go into the `timeline_events` table and appear in the new **Timeline** tab. They can be filtered by date, keyword and evidence item, and the AI agent can query them.

**Check:** `tests/test_extraction.py` covers pcap/pcapng with DNS and HTTP, a FAT disk image with a deleted file, and the memory fallback.

**Not yet tested on real samples:** EVTX and E01, because none are available on this machine.

---

## 8. Shallow multilingual support and encoding problems

**Steps:**

1. **Text encoding** (`decode_text`):
   - Check for a byte-order mark first, then try strict UTF-8, then check for UTF-16 (null bytes), then use `charset-normalizer`.
   - Replacement characters are used only as a last resort.
   - The detected encoding is saved in the item's metadata.
2. **Translating evidence:**
   - `llm_engine.translate_text()` translates in 3,000-character chunks, with instructions to keep names, numbers and IDs unchanged.
   - It runs as a background job, and the result is stored in `evidence_translations`.
   - The original stays the evidence, and translation is a signed audit event.
3. **Searching across languages:** with the "Search across Hindi ↔ English" switch on, `detect_script()` compares the scripts of the query and the evidence. If they differ, `translate_query()` adds a translated query, and each passage keeps its best score. The word index also accepts Devanagari letters.
4. **Interface:** every label in `app.py` is wrapped in `T()`. 153 new Hindi strings were added to `modules/i18n.py`, checked with a script that reads every `T("…")` in the code and finds the ones with no translation.
5. **Hindi PDFs:** reportlab doesn't join Devanagari letters correctly (conjuncts such as क्ष break). Hindi PDFs are now rendered with PyMuPDF's `Story` engine (HarfBuzz text shaping) and the Noto Sans Devanagari font. Reportlab is still used for English.

**Check:**
- UTF-16 and cp1252 decoding tests;
- Hindi full-text search test;
- Hindi PDF font test;
- the app rendered in Hindi with no errors.

---

## 9. AI couldn't use tools

**Method.** Use Ollama's tool calling, with read-only tools limited to the case.

**Steps** ([modules/agent.py](../modules/agent.py)):

1. **Tools defined as JSON function specs:**
   - `search_evidence`, `list_evidence`, `read_evidence` (by character offset);
   - `query_timeline` (time range, keyword, evidence);
   - `filter_records` (a CSV/JSON field equals or contains a value);
   - `get_anomalies`, `get_leads`.
2. **`CaseTools` is created for the one active case.** Every tool result is also saved to a source list.
3. **The loop** (`run_agent`), at most 6 steps:
   1. Send the conversation and the tools to the model.
   2. If the model asks for tools, run them and append the results as `role: tool` messages.
   3. If it answers, stop.
   4. If the step limit is reached, the model is told to answer using what it has.
4. **Check the final answer** with the claim checker (section 5), against everything the tools returned.
5. **UI:** "Agent mode" switch in the chat tab. Each tool call is listed under "Agent steps", and the list is saved with the message.

**Check:** `test_agent_uses_tools_and_answer_is_verified`, with a scripted model. The tool really runs, the true claim stays, and the made-up claim is removed.

---

## 10. Storage and search that didn't scale, and no background queue

**Search steps** ([modules/search_engine.py](../modules/search_engine.py)):

1. **Index at upload:** each document is split into passages (`evidence_passages`) and added to an SQLite **FTS5** full-text index (`passages_fts`). This index is encrypted along with the database.
2. **Small cases (≤ 3,000 passages):** exact TF-IDF over every passage, as before.
3. **Large cases:** FTS5 (BM25 ranking) picks the top 400 passages and the vector index the top 200. Only those candidates go through TF-IDF and get the combined score.
4. **Vector search:** a FAISS index is kept in memory per case.
   - It is rebuilt only when the stored vectors change (count and last indexed time).
   - Up to 50k vectors it uses exact inner product; above that, HNSW.
   - NumPy is the fallback if FAISS isn't available.

**Queue steps** ([modules/jobs.py](../modules/jobs.py)):

1. **`jobs` table** in the encrypted database: status, progress, message, payload, result, error, who started it.
2. **Uploads wait encrypted** in `data/staging/` and are deleted after processing.
3. **Worker threads** (2 by default, `TRACE_JOB_WORKERS`):
   - claim jobs safely (`UPDATE … WHERE status='queued'`);
   - report progress;
   - run as the officer who started the job;
   - write `job_completed` / `job_failed` to the audit log.
4. **Jobs survive restarts:** on startup, jobs left `running` go back to `queued`.
5. **Job types:** `ingest_upload`, `ingest_path` (large server files), `build_index`, `translate_evidence`.
6. **UI:** a "Processing queue" panel refreshes every 3 seconds while jobs are active, and reloads the page when one finishes.

**Check:** `test_large_case_uses_fts_index`, `test_background_ingest_job` (the evidence is saved, the staging file is removed, the right officer is recorded), and `test_server_import_outside_allowed_dirs_is_refused`.

---

## 11. Reports lost on reload

**Steps:**

1. **Table `reports`:** report ID, case, type, title, language, content, cited evidence IDs, claim-check results, SHA-256 of the content, author, time.
2. **Save automatically:** AI drafts are saved as soon as they are generated (`save_report`), and inventory snapshots can be saved too. Each save writes a signed `report_saved` event with the hash.
3. **Versions:** every generation is a new version; nothing is overwritten.
4. **Report tab:** "Saved reports" lists every version with date and author, shows the claim-check results, and offers TXT and PDF downloads.

**Check:** `test_reports_persist`.

---

## Order of work, and how to repeat it

1. Read the code: database, upload processing, search, AI, `app.py`, and the tests.
2. Install the libraries and confirm SQLCipher supports FTS5 and Devanagari.
3. **In parallel:** a helper agent built OCR and the forensic parsers (sections 6–7) in separate files with an agreed interface, while the core was rebuilt:
   - encryption → audit chain → custody → permissions → claim check → agent → search and queue → reports → app screens.
4. Update the tests that depended on the old, unsafe behaviour:
   - case deletion used to wipe the audit log;
   - tests opened the database with plain `sqlite3`;
   - the citation test had no evidence text.
5. Add `tests/test_security.py`, with at least one test per limitation.
6. Rehearse the migration on a copy of the real `data/` folder with temporary keys before touching real data.
7. Render the app as admin and as a viewer, in English and in Hindi, and check for errors.
8. Update the README with the security model and the remaining limits.
