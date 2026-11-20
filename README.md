# TRACE AI

TRACE AI is a local-first prototype for organizing digital evidence, searching extracted text, and drafting evidence-grounded answers. It is an investigator's assistant, not an autonomous case solver or a forensic acquisition tool.

## Run locally

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Linux/macOS (bash/zsh). The bundled `venv/` folder is Windows-only and ignored; create a fresh `.venv`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If `python3 -m venv` fails because `ensurepip` is missing, install the system `python3-venv` package or use a user-installed `virtualenv`:

```bash
pip3 install --user --break-system-packages virtualenv
python3 -m virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the core regression and Streamlit startup checks with:

```bash
python -m unittest discover -s tests -v
```

The app creates an encrypted `data/trace_ai.db` and stores encrypted originals in `data/evidence/`. Keys are in `~/.config/trace_ai`. Back up both, separately, and keep them access-controlled.

Create the first admin with `python -m modules.auth create-admin`.

## Local answer generation (optional)

Evidence upload, extraction, and TF-IDF search work locally without Ollama. AI answer generation requires the Ollama desktop/service to be installed and running, plus the configured model `llama3.2:1b` downloaded on the machine. Semantic retrieval also requires `embeddinggemma` and a one-time semantic-index build. The current code calls Ollama on `http://localhost:11434`; it does not use a hosted LLM API. Set `TRACE_OLLAMA_URL`, `TRACE_CHAT_MODEL`, or `TRACE_EMBEDDING_MODEL` before launching to override the local defaults.

## Security model

| Area | What TRACE AI does |
|---|---|
| Sign-in | Email + password (scrypt), JWT sessions, admin approval of every officer, lockout after 5 failures |
| Case access | Officers see only cases they belong to. Case roles: **viewer** (read), **investigator** (add evidence, chat, notes, reports), **lead** (also delete, manage team). Admins see all cases |
| Encryption at rest | Database encrypted with SQLCipher (AES-256). Evidence originals stored as authenticated AES-256-GCM `.enc` files. Keys live in `~/.config/trace_ai` (override with `TRACE_KEY_DIR` / `TRACE_MASTER_KEY`), **not** in `data/` |
| Audit trail | Every action goes into one append-only hash chain; each entry links to the previous one and is signed with Ed25519. SQL triggers block edits; *Verify audit chain* detects edits that bypass them. Case leads can export a signed bundle, which `tools/verify_audit_bundle.py` checks without TRACE AI |
| Trusted time | Optional RFC 3161 anchoring of the chain head (`TRACE_TSA_URL`; only the hash is sent). Anchors also expose truncation |
| Chain of custody | Upload requires source, acquiring officer, method, time and legal authority (FIR / seizure memo / warrant), plus an optional Section 63 BSA / 65B certificate reference. A supplied acquisition SHA-256 must match the upload or it is rejected. Provenance is write-once; transfers, examinations and working copies are custody events. A custody register can be downloaded |
| AI citations | Every sentence is checked against the passages it cites: names, numbers, dates, emails, IPs, URLs and quoted text must appear in *that* passage, and most key words must match. Unsupported sentences are removed and listed. Optional second check by the local model (`TRACE_LLM_CLAIM_CHECK=1`) |

**First start after upgrading:** an existing plaintext database and plaintext originals are encrypted automatically. The old plaintext copies are moved to `data/pre_encryption_backup/`. Check the app, then securely delete that folder. **Back up the key folder separately.** Without it the encrypted data cannot be recovered.

Existing officers have no case memberships after the upgrade. An admin, or a case lead, adds them from **Case team** in the sidebar.

## Capabilities

- **Evidence types:**
  - Documents: PDF (scanned pages are OCR'd), DOCX, TXT/LOG/CSV/JSON/XML (encoding detected)
  - Images, with OCR
  - Windows event logs (EVTX), network captures (PCAP/PCAPNG)
  - Disk images (E01, raw/dd/img/001): file listing, deleted files, MAC times, small text files
  - Memory dumps (mem/vmem/lime/dmp): Volatility 3 when it can analyse the image, otherwise a strings/IOC scan
- **OCR:** Tesseract (English + Hindi) when installed (`sudo apt install tesseract-ocr tesseract-ocr-hin`), otherwise RapidOCR (offline, Latin script), or an Ollama vision model (`TRACE_OCR_MODEL`).
- **Background jobs:** heavy work runs in a persistent queue in the database and keeps going if you leave the page; jobs left running at shutdown are re-queued on restart. This covers ingestion, OCR, parsing, semantic indexing and translation. Large images can be imported from the server (`TRACE_IMPORT_DIRS`, default `data/import`) instead of uploaded.
- **Timeline:** one UTC timeline built from EVTX, PCAP, filesystem times and CSV/JSON time columns. Timestamps without a time zone are marked "unspecified".
- **Search:**
  - Small cases: exact TF-IDF.
  - Large cases: SQLite FTS5 (BM25) finds the candidates, and only those are ranked.
  - Semantic vectors come from a cached FAISS index (HNSW above 50k chunks).
  - Optional Hindi ↔ English query translation.
- **AI agent** (local Ollama with tool calling): searches, reads evidence, filters the timeline and CSV/JSON records, and reads anomaly flags and leads. Tools are read-only and limited to the active case. Each step is shown, and the answer goes through the citation check.
- **Reports:** AI drafts and inventory snapshots are saved permanently, with version, author, SHA-256 and claim-check results. Hindi PDFs are rendered with proper Devanagari shaping.
- **Translation:** evidence can be machine-translated on demand (stored beside the original, which remains the evidence). The interface is available in English and Hindi.
- **Other:** anomaly review, relationship graph, leads, case diary.

## Remaining limits (be honest in court)

- **What provenance proves:** TRACE AI records and checks acquisition details. It cannot prove that the acquisition itself was lawful or forensically sound. That still needs the certificate and the examiner's testimony.
- **Without RFC 3161 anchoring:** someone with full access to the server and the signing key could rebuild the whole chain. Anchor regularly, and keep the key folder and backups access-controlled.
- **Claim check limits:** the check catches fabricated details and wrong citations. It can miss a sentence that reuses the source's words but misstates their relationship. Investigators must read the cited passages.
- **Analysis gaps:** Windows memory analysis needs Volatility symbol downloads (network), and Linux memory needs ISF symbol files. Without them, memory dumps get a strings scan only. EVTX and E01 parsing have not been tested here against real-world samples.
- **Local AI features:** semantic search, translation, the agent and the Ollama OCR fallback need Ollama running locally.

## No-cost dependencies

Python packages in `requirements.txt` and SQLite are free. PyVis and ReportLab are installed from PyPI when setting up the project. Ollama and its models are also available without a per-request API fee, but Ollama must be installed separately. For semantic retrieval, use Ollama 0.11.10 or newer and download `embeddinggemma` once with `ollama pull embeddinggemma`; the installed model then runs locally. Model downloads require internet and disk space. The app's existing answer model `llama3.2:1b` is a separate local model. No CERT sample data is bundled; provide a lawful dataset sample yourself if you want to compare detections against it.
