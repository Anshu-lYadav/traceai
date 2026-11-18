
import hashlib
import io
import json
from pathlib import Path


IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".bmp",
    ".gif", ".tif", ".tiff",
}


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


def extract_text(filename: str, raw: bytes) -> str:
    ext = Path(filename).suffix.lower()

    if not raw:
        return ""

    if ext in IMAGE_EXTENSIONS:
        return ""

    if ext in (".txt", ".csv"):
        return raw.decode("utf-8-sig", errors="replace").strip()

    if ext == ".json":
        decoded = raw.decode("utf-8-sig", errors="replace")
        try:
            return json.dumps(
                json.loads(decoded),
                indent=2,
                ensure_ascii=False
            )
        except json.JSONDecodeError:
            return decoded.strip()

    if ext == ".pdf":
        import fitz
        with fitz.open(stream=raw, filetype="pdf") as doc:
            pages = []
            for page_number, page in enumerate(doc, start=1):
                page_text = page.get_text("text")
                if page_text.strip():
                    pages.append(f"[Page {page_number}]\n{page_text}")
            return "\n".join(pages).strip()

    if ext == ".docx":
        from docx import Document
        doc = Document(io.BytesIO(raw))

        parts = [
            p.text for p in doc.paragraphs
            if p.text.strip()
        ]

        for table in doc.tables:
            for row in table.rows:
                parts.append(
                    " | ".join(cell.text for cell in row.cells)
                )

        return "\n".join(parts).strip()

    raise ValueError(f"Unsupported format: {ext}")


def process_upload(upload, case_id: str) -> dict:
    raw = upload.getvalue()
    digest = hashlib.sha256(raw).hexdigest()

    metadata = image_metadata(upload.name, raw)
    extracted = extract_text(upload.name, raw)

    return {
        "case_id": case_id,
        "evidence_id": "EV-" + hashlib.sha256(
            f"{case_id}:{digest}".encode("utf-8")
        ).hexdigest()[:12].upper(),
        "filename": upload.name,
        "file_type": Path(upload.name).suffix.lower().lstrip("."),
        "sha256": digest,
        "raw_bytes": len(raw),
        "text": extracted,
        "metadata": metadata,
        "extraction_status": (
            "Image stored (no OCR)" if metadata
            else "Text extracted" if extracted
            else "No text extracted"
        ),
    }
