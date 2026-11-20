"""Text chunking shared by search, indexing, and storage."""

import re


def make_chunks(text, size=900, overlap=120):
    """Divide extracted evidence into overlapping passages."""
    text = re.sub(r"\s+", " ", text or "").strip()
    if not text:
        return []
    passages = []
    start = 0
    chunk_id = 0
    while start < len(text):
        end = min(start + size, len(text))
        passages.append({"chunk_id": chunk_id, "text": text[start:end]})
        if end == len(text):
            break
        start = end - overlap
        chunk_id += 1
    return passages
