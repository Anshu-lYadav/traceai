"""Hybrid evidence retrieval that scales past brute force.

* Small cases (< ``SCAN_LIMIT`` passages): exact word + character TF-IDF over
  every passage, as before.
* Large cases: candidates come from the SQLite FTS5 index (BM25, kept up to date
  at ingestion) plus the approximate-nearest-neighbour vector index; only those
  candidates are re-ranked with TF-IDF.
* Semantic vectors are served from an in-memory FAISS index per case, rebuilt
  only when the stored index changes (exact inner product for small indexes,
  HNSW for large ones). NumPy is the fallback if FAISS is unavailable.
* Optional cross-lingual search translates the query (English ↔ Hindi) with the
  local model and keeps the best score per passage.
"""

from __future__ import annotations

import threading
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from modules.chunking import make_chunks  # noqa: F401  (re-exported for callers/tests)

SCAN_LIMIT = 3000
FTS_CANDIDATES = 400
VECTOR_CANDIDATES = 200
HNSW_THRESHOLD = 50_000

try:
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None

_vector_cache: dict[tuple[str, str], dict[str, Any]] = {}
_vector_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Vector index
# --------------------------------------------------------------------------- #
def _vector_index(case_id: str, model: str) -> dict[str, Any] | None:
    from modules.database import chunk_index_version, list_evidence_chunks

    version = chunk_index_version(case_id, model)
    if version[0] == 0:
        return None
    key = (case_id, model)
    with _vector_lock:
        cached = _vector_cache.get(key)
        if cached and cached["version"] == version:
            return cached
        rows = list_evidence_chunks(case_id, model)
        dimension = rows[0]["dimension"] if rows else 0
        vectors, keys = [], []
        for row in rows:
            vector = np.frombuffer(row["embedding"], dtype=np.float32)
            if vector.size == row["dimension"] == dimension:
                vectors.append(vector)
                keys.append((row["evidence_id"], int(row["chunk_id"])))
        if not vectors:
            return None
        matrix = np.ascontiguousarray(np.vstack(vectors), dtype=np.float32)
        index = None
        if faiss is not None:
            if len(vectors) >= HNSW_THRESHOLD:
                index = faiss.IndexHNSWFlat(dimension, 32, faiss.METRIC_INNER_PRODUCT)
                index.hnsw.efSearch = 128
            else:
                index = faiss.IndexFlatIP(dimension)
            index.add(matrix)
        entry = {"version": version, "index": index, "matrix": None if index else matrix,
                 "keys": keys, "dimension": dimension}
        _vector_cache[key] = entry
        return entry


def _semantic_scores(case_id: str, query: str, limit: int) -> dict[tuple[str, int], float]:
    from modules.embedding_engine import EMBEDDING_MODEL, embed_texts

    entry = _vector_index(case_id, EMBEDDING_MODEL)
    if not entry:
        return {}
    query_vector = embed_texts([query], purpose="query")[0].astype(np.float32)
    if query_vector.size != entry["dimension"]:
        return {}
    k = min(limit, len(entry["keys"]))
    if entry["index"] is not None:
        scores, ids = entry["index"].search(query_vector.reshape(1, -1), k)
        pairs = zip(ids[0], scores[0])
    else:
        sims = entry["matrix"] @ query_vector
        top = np.argsort(-sims)[:k]
        pairs = ((i, sims[i]) for i in top)
    return {entry["keys"][int(i)]: float(np.clip(s, 0.0, 1.0)) for i, s in pairs if i >= 0}


# --------------------------------------------------------------------------- #
# Keyword scoring
# --------------------------------------------------------------------------- #
def _keyword_scores(queries: list[str], documents: list[str]) -> np.ndarray:
    best = np.zeros(len(documents))
    for query in queries:
        try:
            word = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True,
                                   token_pattern=r"(?u)\b[\wऀ-ॿ]{2,}\b")
            word_matrix = word.fit_transform([query] + documents)
            word_scores = cosine_similarity(word_matrix[0:1], word_matrix[1:]).flatten()
        except ValueError:
            word_scores = np.zeros(len(documents))
        try:
            char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
            char_matrix = char.fit_transform([query] + documents)
            char_scores = cosine_similarity(char_matrix[0:1], char_matrix[1:]).flatten()
        except ValueError:
            char_scores = np.zeros(len(documents))
        best = np.maximum(best, 0.80 * word_scores + 0.20 * char_scores)
    return best


def _query_variants(query: str, evidence: list[dict[str, Any]], cross_lingual: bool) -> list[str]:
    if not cross_lingual:
        return [query]
    from modules.llm_engine import detect_script, translate_query

    query_script = detect_script(query)
    sample = " ".join((item.get("text") or "")[:2000] for item in evidence[:20])
    evidence_script = detect_script(sample)
    if query_script in {"unknown", "mixed"} or evidence_script == query_script:
        return [query]
    target = "English" if query_script == "devanagari" else "Hindi"
    translated = translate_query(query, target)
    return [query, translated] if translated else [query]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def _passages_in_memory(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    passages = []
    for item in evidence:
        for chunk in make_chunks(item.get("text", "")):
            passages.append({"evidence_id": item["evidence_id"], "filename": item["filename"],
                             "chunk_id": chunk["chunk_id"], "snippet": chunk["text"]})
    return passages


def _passages_from_index(case_id: str, queries: list[str], semantic: dict) -> list[dict[str, Any]]:
    from modules.database import get_passage, search_passages_fts

    candidates: dict[tuple[str, int], dict[str, Any]] = {}
    for query in queries:
        for row in search_passages_fts(case_id, query, FTS_CANDIDATES):
            candidates.setdefault((row["evidence_id"], row["chunk_id"]), row)
    for key in semantic:
        if key not in candidates:
            passage = get_passage(case_id, key[0], key[1])
            if passage:
                candidates[key] = passage
    return list(candidates.values())


def search_evidence(query, evidence, top_k=5, cross_lingual=False):
    """Return the best matching passages with their evidence IDs and scores."""
    if not query.strip() or not evidence:
        return []

    queries = _query_variants(query, evidence, cross_lingual)
    case_ids = sorted({item.get("case_id") for item in evidence if item.get("case_id")})

    semantic: dict[tuple[str, int], float] = {}
    for case_id in case_ids:
        try:
            for variant in queries[:1]:  # multilingual embeddings need no translation
                semantic.update(_semantic_scores(case_id, variant, VECTOR_CANDIDATES))
        except Exception:
            # Fail closed to keyword search if Ollama/embeddings are unavailable.
            semantic = {}
            break

    total = 0
    if len(case_ids) == 1:
        from modules.database import count_passages
        try:
            total = count_passages(case_ids[0])
        except Exception:
            total = 0
    if total > SCAN_LIMIT:
        passages = _passages_from_index(case_ids[0], queries, semantic)
        scale_mode = "indexed"
    else:
        passages = _passages_in_memory(evidence)
        scale_mode = "full scan"
    if not passages:
        return []

    keyword_scores = _keyword_scores(queries, [p["snippet"] for p in passages])
    if semantic:
        final_scores = np.asarray([
            0.65 * semantic.get((p["evidence_id"], int(p["chunk_id"])), 0.0) + 0.35 * float(k)
            for p, k in zip(passages, keyword_scores)
        ])
        mode = "Hybrid semantic + TF-IDF"
    else:
        final_scores = keyword_scores
        mode = "TF-IDF"
    if len(queries) > 1:
        mode += " · cross-lingual"
    mode += f" · {scale_mode}"

    ranked = sorted(zip(final_scores, passages), key=lambda pair: pair[0], reverse=True)
    results = []
    for score, passage in ranked[:top_k]:
        if score <= 0:
            continue
        results.append({
            "evidence_id": passage["evidence_id"],
            "filename": passage["filename"],
            "chunk_id": passage["chunk_id"],
            "score": round(float(score), 4),
            "retrieval_mode": mode,
            "query_variants": queries,
            "snippet": passage["snippet"],
        })
    return results


def build_semantic_index(evidence, progress=None):
    """Embed all text chunks, then persist them in a single transaction."""
    from modules.database import replace_many_evidence_chunks
    from modules.embedding_engine import EMBEDDING_MODEL, embed_texts

    entries = []
    skipped = 0
    total = max(1, len(evidence))
    for position, item in enumerate(evidence):
        chunks = make_chunks(item.get("text", ""))
        if not chunks:
            skipped += 1
            continue
        case_id = item.get("case_id")
        if not case_id:
            raise ValueError("Evidence is missing its case ID; reload it from the case vault first.")
        vectors = []
        for start in range(0, len(chunks), 32):
            batch = chunks[start:start + 32]
            vectors.extend(embed_texts([chunk["text"] for chunk in batch], purpose="document"))
        entries.append((case_id, item["evidence_id"], EMBEDDING_MODEL, chunks, vectors))
        if progress:
            progress((position + 1) / total, f"Embedded {item['filename']}")

    replace_many_evidence_chunks(entries)
    return {
        "chunks_indexed": sum(len(entry[3]) for entry in entries),
        "files_without_text": skipped,
        "model": EMBEDDING_MODEL,
    }
