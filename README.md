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

The app creates `data/trace_ai.db` and stores uploaded originals in `data/evidence/`. Keep this directory backed up and access controlled. SQLite and the local evidence store do not encrypt data.

## Local answer generation (optional)

Evidence upload, extraction, and TF-IDF search work locally without Ollama. AI answer generation requires the Ollama desktop/service to be installed and running, plus the configured model `llama3.2:1b` downloaded on the machine. Semantic retrieval also requires `embeddinggemma` and a one-time semantic-index build. The current code calls Ollama on `http://localhost:11434`; it does not use a hosted LLM API. Set `TRACE_OLLAMA_URL`, `TRACE_CHAT_MODEL`, or `TRACE_EMBEDDING_MODEL` before launching to override the local defaults.

## Current capabilities

- Create and select separate investigation cases.
- Upload PDF, TXT, CSV, JSON, DOCX, and image files (PNG, JPEG, WebP, BMP, GIF, TIFF).
- Extract text from supported documents and calculate SHA-256 hashes; images retain original files, dimensions, format, mode, and frame count.
- Retain the uploaded original file separately from its extracted text.
- Persist cases, evidence metadata, chat history, and basic activity events in SQLite.
- Delete individual evidence records or whole cases with confirmation; derived indexes and reports are invalidated, chat/audit history is preserved for evidence deletion, and originals are removed only when no other evidence row references them.
- Search evidence passages with local word and character TF-IDF.
- Optionally build a persistent multilingual embedding index with Ollama and hybrid-search semantic plus keyword matches.
- Ask Ollama questions over freshly retrieved passages and display source snippets.
- Run first-pass rule and Isolation Forest anomaly review on CSV/JSON records.
- Explore a NetworkX/PyVis graph of explicit identifiers and possible time-proximity links.
- Generate evidence-linked rule-based leads, record case actions, build a chronological diary, and export draft reports/inventories as text or PDF.
- Select English or Hindi for core interface controls and the local AI answer/report language.
- Download a draft evidence inventory.
- Work inside a full-page crime-investigation console theme with locally bundled case-board artwork and per-section evidence icons.

## Current limitations and handling notes

- Semantic retrieval requires the optional `embeddinggemma` Ollama model; without that model or index, search falls back to TF-IDF. Vectors are stored in SQLite and searched with exact NumPy cosine similarity; FAISS is not used in this Windows/venv build.
- Scanned PDFs and uploaded images need OCR for text extraction; OCR is not included.
- Anomaly review currently handles uploaded CSV/JSON records, not every CERT schema; no CERT dataset is bundled. Timestamp rules need explicit time zones, and statistical flags require investigator review.
- Relationship extraction does not use a named-entity model; it finds common explicit identifiers, emails, IP addresses, and labeled names. A graph edge is a lead for review, not proof of a relationship.
- The English/Hindi toggle covers core interface controls; some explanatory text and evidence content may remain in its source language. Hindi PDF output depends on a compatible Devanagari font installed on the machine.
- The last six chat messages can clarify follow-up references; every turn still retrieves fresh evidence. A citation guard rejects model prose with no valid source ID, but it cannot prove that a cited source entails every claim.
- The activity log is a basic application log, not tamper-evident chain-of-custody evidence.
- Hashes help detect byte changes to a stored copy; they do not prove who acquired the evidence, when it was acquired, or that the acquisition followed forensic procedure.
- Data is stored unencrypted on the local machine. Do not put sensitive real-case data into this prototype until you have an approved storage, access-control, backup, and retention process.
- Treat generated answers and reports as drafts. Investigators must verify every finding against source material; the software must not make guilt determinations or replace qualified forensic examination.

## No-cost dependencies

Python packages in `requirements.txt` and SQLite are free. PyVis and ReportLab are installed from PyPI when setting up the project. Ollama and its models are also available without a per-request API fee, but Ollama must be installed separately. For semantic retrieval, use Ollama 0.11.10 or newer and download `embeddinggemma` once with `ollama pull embeddinggemma`; the installed model then runs locally. Model downloads require internet and disk space. The app's existing answer model `llama3.2:1b` is a separate local model. No CERT sample data is bundled; provide a lawful dataset sample yourself if you want to compare detections against it.
