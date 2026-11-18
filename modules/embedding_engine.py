"""Local Ollama embedding calls and vector normalization."""

from __future__ import annotations

import os

import numpy as np
import requests


OLLAMA_BASE_URL = os.environ.get("TRACE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_EMBED_URL = f"{OLLAMA_BASE_URL}/api/embed"
EMBEDDING_MODEL = os.environ.get("TRACE_EMBEDDING_MODEL", "embeddinggemma")
DOCUMENT_PREFIX = "title: none | text: "
QUERY_PREFIX = "task: search result | query: "


def embed_texts(texts: list[str], purpose: str = "document") -> list[np.ndarray]:
    if not texts:
        return []
    if purpose not in {"document", "query"}:
        raise ValueError("Purpose must be 'document' or 'query'.")
    prefix = DOCUMENT_PREFIX if purpose == "document" else QUERY_PREFIX
    try:
        response = requests.post(
            OLLAMA_EMBED_URL,
            json={
                "model": EMBEDDING_MODEL,
                "input": [prefix + text for text in texts],
                "truncate": False,
            },
            timeout=240,
        )
        response.raise_for_status()
        raw_vectors = response.json().get("embeddings", [])
        if len(raw_vectors) != len(texts):
            raise RuntimeError("Ollama returned a different number of vectors than requested.")
        matrix = np.asarray(raw_vectors, dtype=np.float32)
        if matrix.ndim != 2 or not np.isfinite(matrix).all():
            raise RuntimeError("Ollama returned invalid embedding vectors.")
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        if np.any(norms == 0):
            raise RuntimeError("Ollama returned a zero-length embedding vector.")
        matrix = matrix / norms
        return [matrix[index] for index in range(matrix.shape[0])]
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            "Cannot connect to Ollama. Start Ollama, install its embedding model, and retry."
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("Ollama embedding request timed out. Try indexing fewer files at once.") from exc
    except requests.exceptions.HTTPError as exc:
        body = getattr(exc.response, "text", "")
        if "not found" in body.lower() or "pull" in body.lower():
            raise RuntimeError(
                f"Embedding model '{EMBEDDING_MODEL}' is not available in Ollama. "
                f"Pull it once, then retry. Details: {body[:300]}"
            ) from exc
        raise RuntimeError(f"Ollama embedding request failed: {body[:300]}") from exc

