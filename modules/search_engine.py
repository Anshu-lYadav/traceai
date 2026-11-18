
import re
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def make_chunks(text, size=900, overlap=120):
    """
    Divide extracted evidence into smaller passages.
    """

    text = re.sub(r"\s+", " ", text).strip()

    if not text:
        return []

    passages = []
    start = 0
    chunk_id = 0

    while start < len(text):

        end = min(start + size, len(text))

        passages.append({
            "chunk_id": chunk_id,
            "text": text[start:end]
        })

        if end == len(text):
            break

        start = end - overlap
        chunk_id += 1

    return passages


def search_evidence(query, evidence, top_k=5):
    """
    Hybrid local retrieval:
    1. Word-based TF-IDF
    2. Character-based TF-IDF

    Returns matching evidence passages with source IDs.
    """

    if not query.strip() or not evidence:
        return []

    passages = []

    # Divide every evidence document into chunks
    for item in evidence:

        chunks = make_chunks(item["text"])

        for chunk in chunks:

            passages.append({
                "evidence_id": item["evidence_id"],
                "filename": item["filename"],
                "chunk_id": chunk["chunk_id"],
                "snippet": chunk["text"]
            })

    if not passages:
        return []

    documents = [p["snippet"] for p in passages]

    try:

        # Word-based retrieval
        word_vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True
        )

        word_matrix = word_vectorizer.fit_transform(
            [query] + documents
        )

        word_scores = cosine_similarity(
            word_matrix[0:1],
            word_matrix[1:]
        ).flatten()

        # Character-based retrieval
        char_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            sublinear_tf=True
        )

        char_matrix = char_vectorizer.fit_transform(
            [query] + documents
        )

        char_scores = cosine_similarity(
            char_matrix[0:1],
            char_matrix[1:]
        ).flatten()

        # Combine both retrieval scores
        keyword_scores = (
            0.80 * word_scores +
            0.20 * char_scores
        )

    except ValueError:
        return []

    # Sort results by relevance
    final_scores = keyword_scores
    retrieval_mode = "TF-IDF"

    # When a local semantic index exists, blend vector similarity with the
    # existing keyword/character search. Fail closed to TF-IDF if Ollama is down.
    case_ids = {item.get("case_id") for item in evidence if item.get("case_id")}
    if case_ids:
        try:
            from modules.database import list_evidence_chunks
            from modules.embedding_engine import EMBEDDING_MODEL, embed_texts

            indexed_chunks = []
            for case_id in sorted(case_ids):
                indexed_chunks.extend(list_evidence_chunks(case_id, EMBEDDING_MODEL))
            if indexed_chunks:
                query_vector = embed_texts([query], purpose="query")[0]
                semantic_scores = {}
                for row in indexed_chunks:
                    vector = np.frombuffer(row["embedding"], dtype=np.float32)
                    if vector.size != row["dimension"] or vector.size != query_vector.size:
                        continue
                    semantic_scores[(row["evidence_id"], row["chunk_id"])] = float(
                        np.clip(np.dot(vector, query_vector), 0.0, 1.0)
                    )
                if semantic_scores:
                    final_scores = np.asarray([
                        0.65 * semantic_scores.get((passage["evidence_id"], passage["chunk_id"]), 0.0)
                        + 0.35 * float(keyword_score)
                        for passage, keyword_score in zip(passages, keyword_scores)
                    ])
                    retrieval_mode = "Hybrid semantic + TF-IDF"
        except Exception:
            # Preserve usable local keyword search when embedding service/model is unavailable.
            pass

    ranked_results = sorted(
        zip(final_scores, passages),
        key=lambda item: item[0],
        reverse=True
    )

    results = []

    for score, passage in ranked_results[:top_k]:

        if score <= 0:
            continue

        results.append({
            "evidence_id": passage["evidence_id"],
            "filename": passage["filename"],
            "chunk_id": passage["chunk_id"],
            "score": round(float(score), 4),
            "retrieval_mode": retrieval_mode,
            "snippet": passage["snippet"]
        })

    return results


def build_semantic_index(evidence):
    """Embed all text chunks, then persist them in a single transaction."""
    from modules.database import replace_many_evidence_chunks
    from modules.embedding_engine import EMBEDDING_MODEL, embed_texts

    entries = []
    skipped = 0
    for item in evidence:
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

    replace_many_evidence_chunks(entries)
    return {
        "chunks_indexed": sum(len(entry[3]) for entry in entries),
        "files_without_text": skipped,
        "model": EMBEDDING_MODEL,
    }
