"""Offline-first OCR helpers for TRACE AI.

Engine preference: Tesseract (if the binary is installed) -> RapidOCR
(onnxruntime, fully offline) -> an Ollama vision model (only when
TRACE_OCR_MODEL is set and the Ollama server answers).
"""

from __future__ import annotations

import base64
import io
import os
import shutil
import threading
from functools import lru_cache

MAX_SIDE = 4000
DEFAULT_LANGUAGES = ("eng", "hin")
OLLAMA_PROMPT = (
    "Transcribe all text visible in this image verbatim. "
    "Output only the transcribed text, with no commentary. "
    "If there is no text, output nothing."
)

_rapid_lock = threading.Lock()
_rapid_engine = None
_rapid_failed = False


def _ollama_url() -> str:
    url = os.environ.get("TRACE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
    if not url.startswith(("http://", "https://")):
        return ""
    return url


@lru_cache(maxsize=1)
def _tesseract_languages() -> tuple[str, ...]:
    if not shutil.which("tesseract"):
        return ()
    try:
        import pytesseract
        return tuple(sorted(pytesseract.get_languages(config="")))
    except Exception:
        return ()


def _rapidocr_importable() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except Exception:
        return False


def _get_rapidocr():
    global _rapid_engine, _rapid_failed
    if _rapid_engine is not None or _rapid_failed:
        return _rapid_engine
    with _rapid_lock:
        if _rapid_engine is None and not _rapid_failed:
            try:
                from rapidocr_onnxruntime import RapidOCR
                _rapid_engine = RapidOCR()
            except Exception:
                _rapid_failed = True
    return _rapid_engine


def _ollama_reachable(timeout: float = 1.5) -> bool:
    model = os.environ.get("TRACE_OCR_MODEL", "").strip()
    url = _ollama_url()
    if not model or not url:
        return False
    try:
        import requests
        response = requests.get(f"{url}/api/tags", timeout=timeout)
        return response.ok
    except Exception:
        return False


def ocr_status() -> dict:
    """Report which OCR engines are usable on this machine."""
    tesseract_binary = shutil.which("tesseract")
    languages = list(_tesseract_languages())
    model = os.environ.get("TRACE_OCR_MODEL", "").strip()
    ollama_ok = _ollama_reachable() if model else False
    engines = []
    if tesseract_binary and languages:
        engines.append("tesseract")
    if _rapidocr_importable():
        engines.append("rapidocr")
    if ollama_ok:
        engines.append("ollama")
    return {
        "tesseract": {
            "available": bool(tesseract_binary and languages),
            "binary": tesseract_binary,
            "languages": languages,
            "hindi": "hin" in languages,
        },
        "rapidocr": {"available": "rapidocr" in engines},
        "ollama": {
            "available": ollama_ok,
            "model": model or None,
            "url": _ollama_url() or None,
        },
        "engines": engines,
        "any_available": bool(engines),
    }


def _prepare(raw: bytes):
    from PIL import Image, ImageOps

    with Image.open(io.BytesIO(raw)) as image:
        image.seek(0)
        image = ImageOps.exif_transpose(image)
        if image.mode in ("RGBA", "LA", "P"):
            rgba = image.convert("RGBA")
            background = Image.new("RGB", rgba.size, (255, 255, 255))
            background.paste(rgba, mask=rgba.split()[-1])
            image = background
        else:
            image = image.convert("RGB")
        largest = max(image.size)
        if largest > MAX_SIDE:
            scale = MAX_SIDE / largest
            image = image.resize(
                (max(1, int(image.width * scale)), max(1, int(image.height * scale))),
                Image.LANCZOS,
            )
        return image.copy()


def _ocr_tesseract(image, languages) -> str:
    available = _tesseract_languages()
    if not available:
        return ""
    chosen = [lang for lang in languages if lang in available] or (
        ["eng"] if "eng" in available else []
    )
    if not chosen:
        return ""
    import pytesseract
    return pytesseract.image_to_string(image, lang="+".join(chosen)).strip()


def _ocr_rapid(image) -> str:
    engine = _get_rapidocr()
    if engine is None:
        return ""
    import numpy as np
    result, _ = engine(np.array(image))
    if not result:
        return ""
    # Group boxes into lines by vertical position, then order left-to-right.
    boxes = []
    for box, text, _score in result:
        ys = [point[1] for point in box]
        xs = [point[0] for point in box]
        boxes.append(((min(ys) + max(ys)) / 2, min(xs), max(ys) - min(ys), text))
    boxes.sort()
    lines: list[list[tuple]] = []
    for box in boxes:
        if lines and abs(box[0] - lines[-1][0][0]) < max(box[2], lines[-1][0][2]) * 0.5:
            lines[-1].append(box)
        else:
            lines.append([box])
    return "\n".join(
        " ".join(entry[3] for entry in sorted(line, key=lambda b: b[1]))
        for line in lines
    ).strip()


def _ocr_ollama(image) -> str:
    if not _ollama_reachable():
        return ""
    import requests
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    payload = {
        "model": os.environ["TRACE_OCR_MODEL"].strip(),
        "stream": False,
        "messages": [{
            "role": "user",
            "content": OLLAMA_PROMPT,
            "images": [base64.b64encode(buffer.getvalue()).decode("ascii")],
        }],
        "options": {"temperature": 0},
    }
    response = requests.post(f"{_ollama_url()}/api/chat", json=payload, timeout=300)
    response.raise_for_status()
    return (response.json().get("message", {}).get("content") or "").strip()


def ocr_image_bytes(raw: bytes, languages=DEFAULT_LANGUAGES) -> tuple[str, str]:
    """OCR an encoded image. Returns (text, engine_name) or ("", "none")."""
    if not raw:
        return "", "none"
    try:
        image = _prepare(raw)
    except Exception:
        return "", "none"

    for name, runner in (
        ("tesseract", lambda: _ocr_tesseract(image, tuple(languages))),
        ("rapidocr", lambda: _ocr_rapid(image)),
        ("ollama", lambda: _ocr_ollama(image)),
    ):
        try:
            text = runner()
        except Exception:
            text = ""
        if text:
            return text, name
    return "", "none"
