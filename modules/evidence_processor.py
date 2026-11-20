import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from modules import forensics
from modules.forensics import (
    DISK_EXTENSIONS,
    EVTX_EXTENSIONS,
    MAX_TEXT_CHARS,
    MAX_TIMELINE,
    MEMORY_EXTENSIONS,
    PCAP_EXTENSIONS,
)


IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".bmp",
    ".gif", ".tif", ".tiff",
}
TEXT_EXTENSIONS = {".txt", ".csv", ".log", ".json", ".xml"}
DOCUMENT_EXTENSIONS = {".pdf", ".docx"}

# Disk images and memory dumps: register by server-side path, not browser upload.
LARGE_FILE_EXTENSIONS = set(DISK_EXTENSIONS) | set(MEMORY_EXTENSIONS)
SUPPORTED_EXTENSIONS = (
    TEXT_EXTENSIONS | DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS
    | set(EVTX_EXTENSIONS) | set(PCAP_EXTENSIONS) | LARGE_FILE_EXTENSIONS
)

HASH_BLOCK = 4 * 1024 * 1024
PDF_OCR_MIN_CHARS = 25
PDF_OCR_MAX_PAGES = 200
PDF_OCR_DPI = 200
OCR_MIN_WIDTH = 32
OCR_MIN_HEIGHT = 16

Progress = Callable[[float, str], None] | None


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------

def image_metadata(filename: str, raw: bytes) -> dict:
    ext = Path(filename).suffix.lower()
    if ext not in IMAGE_EXTENSIONS or not raw:
        return {}

    from PIL import Image

    try:
        with Image.open(io.BytesIO(raw)) as image:
            width, height = image.size
            return {
                "width": width,
                "height": height,
                "format": (image.format or ext.lstrip(".")).upper(),
                "mode": image.mode,
                "frames": getattr(image, "n_frames", 1),
            }
    except (OSError, ValueError) as exc:
        raise ValueError(f"Invalid image file '{filename}': {exc}") from exc


def _analyse_image(filename: str, raw: bytes) -> dict:
    metadata = image_metadata(filename, raw)
    warnings: list[str] = []
    if not metadata:
        return _blank("Image stored (no OCR)")
    if metadata["width"] < OCR_MIN_WIDTH or metadata["height"] < OCR_MIN_HEIGHT:
        metadata["ocr"] = {"engine": "none", "skipped": "image too small to contain text"}
        status = "Image stored (no OCR)"
        text = ""
    else:
        from modules.ocr import ocr_image_bytes, ocr_status

        text, engine = ocr_image_bytes(raw)
        if metadata.get("frames", 1) > 1:
            warnings.append("Only the first frame of a multi-frame image was OCR'd")
        if text:
            status = f"Text extracted (OCR: {engine})"
            metadata["ocr"] = {"engine": engine, "characters": len(text)}
        elif ocr_status()["any_available"]:
            status = "Image stored (no text found)"
            metadata["ocr"] = {"engine": "none", "text_found": False}
        else:
            status = "Image stored (no OCR)"
            metadata["ocr"] = {"engine": "none", "skipped": "no OCR engine available"}
    metadata["warnings"] = warnings
    return {"text": text, "timeline": [], "metadata": metadata, "status": status}


# --------------------------------------------------------------------------
# Text decoding
# --------------------------------------------------------------------------

_BOMS = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def decode_text(raw: bytes) -> tuple[str, str]:
    """Decode bytes to text. Returns (text, encoding_label)."""
    for bom, codec in _BOMS:
        if raw.startswith(bom):
            return raw[len(bom):].decode(codec.replace("-sig", ""), errors="replace"), f"{codec} (BOM)"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    sample = raw[:4096]
    if len(sample) >= 4:
        odd_nuls = sample[1::2].count(0) / max(1, len(sample[1::2]))
        even_nuls = sample[0::2].count(0) / max(1, len(sample[0::2]))
        if odd_nuls > 0.3 and even_nuls < 0.05:
            return raw.decode("utf-16-le", errors="replace"), "utf-16-le (detected)"
        if even_nuls > 0.3 and odd_nuls < 0.05:
            return raw.decode("utf-16-be", errors="replace"), "utf-16-be (detected)"
    try:
        from charset_normalizer import from_bytes

        results = list(from_bytes(raw[:2_000_000]))
        if results:
            # Single-byte code pages are easily confused on short samples: among
            # near-equally clean candidates take the most coherent, preferring
            # the common Windows Western code page on ties.
            floor = min(r.chaos for r in results)
            near = [r for r in results if r.chaos <= floor + 0.1]
            best = max(near, key=lambda r: (r.coherence, r.encoding == "cp1252", -r.chaos))
            return raw.decode(best.encoding, errors="replace"), best.encoding
    except Exception:
        pass
    return raw.decode("utf-8", errors="replace"), "utf-8 (with replacement)"


# --------------------------------------------------------------------------
# Timestamps in CSV / JSON
# --------------------------------------------------------------------------

_TIME_KEYS = {
    "timestamp", "time", "date", "datetime", "createdat", "created", "timecreated",
    "eventtime", "ts", "utctime", "updatedat", "loggedat", "occurredat",
    "starttime", "logtime", "datetimeutc", "timeutc", "timestamputc", "systemtime",
    "receivedat", "sentat", "time_stamp",
}


def _is_time_key(name: str) -> bool:
    normalized = re.sub(r"[^a-z]", "", str(name).lower())
    return normalized in _TIME_KEYS or normalized.endswith("timestamp")


def parse_timestamp(value) -> tuple[str, bool] | None:
    """Return (iso_string, timezone_known) or None if not a timestamp."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value.strip())):
        number = float(value)
        if number > 1e11:
            number /= 1000.0  # epoch milliseconds
        iso = forensics.iso_utc(number)
        return (iso, True) if iso and number > 3e8 else None
    text = str(value).strip()
    if not text or len(text) > 64 or not re.search(r"\d{1,4}", text):
        return None
    moment = None
    candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        moment = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            from dateutil import parser as date_parser

            moment = date_parser.parse(text)
        except (ValueError, OverflowError, TypeError, ImportError):
            return None
    if moment.year < 1971 or moment.year > 2200:
        return None
    if moment.tzinfo is not None and moment.utcoffset() is not None:
        return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), True
    return moment.isoformat(timespec="seconds"), False


def _records_timeline(rows, source: str, warnings: list[str]) -> list[dict]:
    """rows: iterable of dicts. One timeline entry per row with a parsable timestamp."""
    timeline: list[dict] = []
    time_key = None
    dropped = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if time_key is None:
            time_key = next((k for k in row if k is not None and _is_time_key(k)), None)
            if time_key is None:
                return []
        parsed = parse_timestamp(row.get(time_key))
        if not parsed:
            continue
        if len(timeline) >= MAX_TIMELINE:
            dropped += 1
            continue
        iso, known_tz = parsed
        fields = {}
        for key, value in row.items():
            if key is None or key == time_key or len(fields) >= 8:
                continue
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            if value not in (None, ""):
                fields[str(key)[:60]] = str(value)[:200]
        summary = ", ".join(f"{k}={v}" for k, v in list(fields.items())[:4])[:300]
        if not known_tz:
            fields["timezone"] = "unspecified"
        timeline.append({
            "timestamp": iso,
            "summary": summary or f"{time_key} record",
            "source": source,
            "fields": fields,
        })
    if dropped:
        warnings.append(f"Timeline capped at {MAX_TIMELINE:,} entries ({dropped:,} more omitted)")
    return timeline


def _json_records(data):
    if isinstance(data, list) and any(isinstance(item, dict) for item in data[:50]):
        return data
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and any(isinstance(item, dict) for item in value[:50]):
                return value
        return [data]
    return []


# --------------------------------------------------------------------------
# Per-format extraction
# --------------------------------------------------------------------------

def _blank(status: str = "No text extracted", **metadata) -> dict:
    metadata.setdefault("warnings", [])
    return {"text": "", "timeline": [], "metadata": metadata, "status": status}


def _analyse_text(ext: str, raw: bytes) -> dict:
    decoded, encoding = decode_text(raw)
    warnings: list[str] = []
    if "replacement" in encoding:
        warnings.append("Encoding could not be determined; undecodable bytes replaced")
    metadata = {"encoding": encoding, "warnings": warnings}
    timeline: list[dict] = []
    text = decoded.strip()

    if ext == ".json":
        try:
            data = json.loads(decoded)
            text = json.dumps(data, indent=2, ensure_ascii=False)
            timeline = _records_timeline(_json_records(data), "json", warnings)
        except json.JSONDecodeError:
            records = []
            for line in decoded.splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records = []
                        break
            if records:
                metadata["json_lines"] = len(records)
                timeline = _records_timeline(records, "json", warnings)
            else:
                warnings.append("Invalid JSON; stored as plain text")
    elif ext == ".csv":
        try:
            sample = decoded[:8192]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            csv.field_size_limit(10_000_000)
            reader = csv.DictReader(io.StringIO(decoded), dialect=dialect)
            timeline = _records_timeline(reader, "csv", warnings)
            if reader.fieldnames:
                metadata["columns"] = [str(c) for c in reader.fieldnames][:100]
        except csv.Error as exc:
            warnings.append(f"CSV parsing stopped early: {exc}")

    status = "Text extracted" if text else "No text extracted"
    return {"text": text, "timeline": timeline, "metadata": metadata, "status": status}


def _analyse_pdf(raw: bytes) -> dict:
    import fitz

    warnings: list[str] = []
    try:
        doc = fitz.open(stream=raw, filetype="pdf")
    except Exception as exc:
        raise ValueError(f"Invalid PDF file: {exc}") from exc
    pages: list[str] = []
    ocr_pages = 0
    ocr_engine = None
    ocr_attempted = 0
    skipped_ocr = 0
    with doc:
        if doc.needs_pass:
            warnings.append("PDF is password-protected; no text could be extracted")
            return _blank("No text extracted (encrypted PDF)", page_count=doc.page_count,
                          warnings=warnings)
        for page_number, page in enumerate(doc, start=1):
            try:
                page_text = page.get_text("text")
            except Exception as exc:
                warnings.append(f"Page {page_number}: text layer unreadable ({exc})")
                page_text = ""
            if len(re.sub(r"\s", "", page_text)) >= PDF_OCR_MIN_CHARS:
                pages.append(f"[Page {page_number}]\n{page_text}")
                continue
            if ocr_attempted >= PDF_OCR_MAX_PAGES:
                skipped_ocr += 1
                if page_text.strip():
                    pages.append(f"[Page {page_number}]\n{page_text}")
                continue
            ocr_attempted += 1
            text = ""
            try:
                from modules.ocr import ocr_image_bytes

                pixmap = page.get_pixmap(dpi=PDF_OCR_DPI)
                text, engine = ocr_image_bytes(pixmap.tobytes("png"))
            except Exception as exc:
                warnings.append(f"Page {page_number}: OCR failed ({exc})")
                engine = "none"
            if text:
                ocr_pages += 1
                ocr_engine = engine
                body = page_text.strip()
                pages.append(f"[Page {page_number} — OCR]\n" + (f"{body}\n" if body else "") + text)
            elif page_text.strip():
                pages.append(f"[Page {page_number}]\n{page_text}")
        page_count = doc.page_count
    if skipped_ocr:
        warnings.append(f"OCR limited to {PDF_OCR_MAX_PAGES} pages; {skipped_ocr} more "
                        "low-text pages were not OCR'd")
    text = "\n".join(pages).strip()
    metadata = {"page_count": page_count, "ocr_pages": ocr_pages, "warnings": warnings}
    if ocr_engine:
        metadata["ocr_engine"] = ocr_engine
    if not text:
        status = "No text extracted"
    elif ocr_pages:
        status = f"Text extracted (OCR: {ocr_engine})"
    else:
        status = "Text extracted"
    return {"text": text, "timeline": [], "metadata": metadata, "status": status}


def _analyse_docx(raw: bytes) -> dict:
    from docx import Document

    try:
        doc = Document(io.BytesIO(raw))
    except Exception as exc:
        raise ValueError(f"Invalid DOCX file: {exc}") from exc
    parts = [p.text for p in doc.paragraphs if p.text.strip()]
    for table in doc.tables:
        for row in table.rows:
            parts.append(" | ".join(cell.text for cell in row.cells))
    text = "\n".join(parts).strip()
    return {"text": text, "timeline": [], "metadata": {"warnings": []},
            "status": "Text extracted" if text else "No text extracted"}


def _analyse(filename: str, raw: bytes | None = None, path: Path | None = None,
             progress: Progress = None) -> dict:
    """Dispatch on extension. Exactly one of raw / path is given."""
    ext = Path(filename).suffix.lower()
    source = raw if raw is not None else path

    if ext in EVTX_EXTENSIONS:
        return forensics.parse_evtx(source, progress)
    if ext in PCAP_EXTENSIONS:
        return forensics.parse_pcap(source, progress)
    if ext == ".raw":
        with forensics.as_path(source, ".raw") as temp_path:
            if forensics.looks_like_filesystem_image(temp_path):
                return forensics.parse_disk_image(temp_path, filename, progress)
            return forensics.analyze_memory(temp_path, filename, progress)
    if ext in DISK_EXTENSIONS:
        return forensics.parse_disk_image(source, filename, progress)
    if ext in MEMORY_EXTENSIONS:
        return forensics.analyze_memory(source, filename, progress)

    if raw is None:
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(f"Unsupported format: {ext}")
        raw = Path(path).read_bytes()
    if not raw:
        return _blank()
    if ext in IMAGE_EXTENSIONS:
        return _analyse_image(filename, raw)
    if ext in TEXT_EXTENSIONS:
        return _analyse_text(ext, raw)
    if ext == ".pdf":
        return _analyse_pdf(raw)
    if ext == ".docx":
        return _analyse_docx(raw)
    raise ValueError(f"Unsupported format: {ext}")


def _finalise(result: dict) -> dict:
    metadata = result.get("metadata") or {}
    warnings = metadata.setdefault("warnings", [])
    text = result.get("text") or ""
    if len(text) > MAX_TEXT_CHARS:
        omitted = len(text) - MAX_TEXT_CHARS
        text = text[:MAX_TEXT_CHARS] + f"\n[truncated {omitted:,} characters: text limit is {MAX_TEXT_CHARS:,}]"
        metadata["text_truncated"] = True
        warnings.append(f"Extracted text truncated to {MAX_TEXT_CHARS:,} characters")
    timeline = result.get("timeline") or []
    if len(timeline) > MAX_TIMELINE:
        warnings.append(f"Timeline truncated to {MAX_TIMELINE:,} entries")
        metadata["timeline_truncated"] = True
        timeline = timeline[:MAX_TIMELINE]
    result.update(text=text, timeline=timeline, metadata=metadata)
    return result


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def extract_text(filename: str, raw: bytes) -> str:
    if not raw:
        return ""
    return _finalise(_analyse(filename, raw=raw))["text"]


def _evidence_id(case_id: str, digest: str) -> str:
    return "EV-" + hashlib.sha256(f"{case_id}:{digest}".encode("utf-8")).hexdigest()[:12].upper()


def _item(case_id: str, filename: str, digest: str, size: int, result: dict) -> dict:
    return {
        "case_id": case_id,
        "evidence_id": _evidence_id(case_id, digest),
        "filename": filename,
        "file_type": Path(filename).suffix.lower().lstrip("."),
        "sha256": digest,
        "raw_bytes": size,
        "text": result["text"],
        "metadata": result["metadata"],
        "extraction_status": result["status"],
        "timeline": result["timeline"],
    }


def process_upload(upload, case_id: str) -> dict:
    raw = upload.getvalue()
    digest = hashlib.sha256(raw).hexdigest()
    result = _finalise(_analyse(upload.name, raw=raw) if raw else _blank())
    return _item(case_id, upload.name, digest, len(raw), result)


def process_path(path: Path, case_id: str, filename: str | None = None,
                 progress: Progress = None) -> dict:
    """Process a (possibly very large) file on the server's filesystem."""
    path = Path(path)
    filename = filename or path.name
    if not path.is_file():
        raise ValueError(f"Evidence path is not a readable file: {path}")
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported format: {ext}")
    size = path.stat().st_size
    hasher = hashlib.sha256()
    done = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(HASH_BLOCK)
            if not block:
                break
            hasher.update(block)
            done += len(block)
            if progress:
                try:
                    progress(0.3 * done / max(1, size), f"Hashing: {done // (1024 * 1024):,} MB")
                except Exception:
                    pass
    digest = hasher.hexdigest()

    def scaled(fraction: float, message: str) -> None:
        if progress:
            progress(0.3 + 0.7 * fraction, message)

    result = _blank() if size == 0 else _analyse(filename, path=path, progress=scaled)
    result = _finalise(result)
    if progress:
        try:
            progress(1.0, result["status"])
        except Exception:
            pass
    return _item(case_id, filename, digest, size, result)
