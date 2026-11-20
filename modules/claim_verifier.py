"""Claim-level verification of AI output against the evidence it cites.

The old guard only checked that *some* valid ``[EV-…]`` tag appeared, so a
model could attach a fabricated claim to a real tag.  This module checks every
sentence separately:

1. Every cited ID must be one of the passages the model was actually given.
2. Specific details in the sentence — names, numbers, dates/times, e-mail
   addresses, IP addresses, URLs, quoted text, identifiers — must literally
   appear in the cited passages (not in some other passage).
3. Most content words of the sentence must appear in the cited passages
   (skipped when the claim and the evidence are in different scripts, e.g. a
   Hindi answer over English records; then only identifiers are checked).
4. Optionally (``TRACE_LLM_CLAIM_CHECK=1``) a local model is asked whether the
   cited passage entails the sentence; it can only remove claims, never add.

Unsupported sentences are replaced by a visible warning, so a reader never
sees an unverified statement presented as a finding.  This is a strong filter,
not a proof: a sentence can reuse the passage's words and still misstate the
relationship between them, so investigators must still read the sources.
"""

from __future__ import annotations

import os
import re
from typing import Any

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

CITATION_RE = re.compile(r"\[?\b(EV-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b\]?", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\])>,]+")
_NUMBER_RE = re.compile(r"(?<![\w-])\d[\d:/.,-]*\d(?![\w])|(?<![\w.-])\d{2,}(?![\w])")
_QUOTED_RE = re.compile(r"[\"“”']([^\"“”']{4,80})[\"“”']")
_ID_RE = re.compile(r"\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{3,}\b")
_CAPITAL_RE = re.compile(r"\b[A-Z][a-zA-Z'’-]+\b")
_WORD_RE = re.compile(r"[A-Za-z\u0900-\u097F]{4,}")
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")
_LATIN_RE = re.compile(r"[A-Za-z]")

_REFUSAL_RE = re.compile(
    r"\b(insufficient evidence|not enough evidence|cannot answer|cannot determine|cannot be "
    r"(?:established|determined|confirmed)|no relevant evidence|unable to answer|not established|"
    r"no (?:evidence|record)s? (?:of|for|about|shows?|indicat)|unverified|not supported|unclear|"
    r"none (?:is|are) apparent|no contradictions?|does not (?:show|establish|indicate))\b",
    re.I,
)
_GENERIC_CAPITALS = {
    # Generic words often capitalized in reports; they are not checkable details.
    "evidence", "record", "records", "file", "files", "log", "logs", "user", "users", "email",
    "message", "messages", "report", "case", "investigation", "investigator", "findings",
    "finding", "observations", "observation", "conclusion", "interpretation", "interpretations",
    "contradictions", "contradiction", "gaps", "limitations", "confirmed", "possible", "however",
    "according", "based", "source", "sources", "document", "documents", "data", "analysis",
    "timeline", "network", "system", "account", "device", "police", "officer", "suspect",
    "victim", "witness", "date", "time", "english", "hindi", "trace", "summary", "neutral",
    "scope", "reviewed", "unverified", "leads", "lead", "missing", "information", "supplied",
    "passage", "passages", "id", "ids", "csv", "json", "pdf", "txt", "the", "this", "that",
    "these", "those", "there", "it", "they", "both", "each", "also", "additionally", "while",
    "although", "because", "since", "if", "when", "where", "who", "what", "which", "no", "not",
    "yes", "note", "notes", "event", "events", "activity", "access", "accessed", "login",
    "january", "february", "march", "april", "may", "june", "july", "august", "september",
    "october", "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday", "utc", "ist", "am", "pm", "ai", "llm", "ok",
}
_STOP = set(ENGLISH_STOP_WORDS) | _GENERIC_CAPITALS


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower())


def _split_line(line: str) -> list[str]:
    """Split one line into sentences, keeping trailing citation-only fragments attached."""
    parts = re.split(r"(?<=[.!?।])\s+(?=[\"“(\[]?[A-Z\u0900-\u097F0-9*-])", line)
    sentences: list[str] = []
    for part in parts:
        if sentences and re.fullmatch(r"(?:\s*\[?EV-[A-Z0-9-]+\]?[\s.,;]*)+", part, re.I):
            sentences[-1] = sentences[-1] + " " + part
        else:
            sentences.append(part)
    return sentences


def _is_heading(sentence: str) -> bool:
    plain = re.sub(r"^[\s#>*_\-\d.)]+", "", sentence).strip().strip("*_ ")
    if not plain:
        return True
    if plain.endswith(":") and len(plain.split()) <= 8:
        return True
    words = plain.split()
    return len(words) <= 6 and not CITATION_RE.search(plain) and (
        plain.isupper() or plain.istitle() or re.match(r"^\d+[.)]", sentence.strip()) is not None
    )


def specific_details(sentence: str) -> list[str]:
    text = CITATION_RE.sub(" ", sentence)
    details: list[str] = []
    details += _EMAIL_RE.findall(text)
    details += _URL_RE.findall(text)
    details += _IP_RE.findall(text)
    scrubbed = _EMAIL_RE.sub(" ", _URL_RE.sub(" ", _IP_RE.sub(" ", text)))
    details += [n.strip(".,:-/") for n in _NUMBER_RE.findall(scrubbed)]
    details += _QUOTED_RE.findall(text)
    details += [token for token in _ID_RE.findall(scrubbed) if not token.isdigit()]
    body = re.sub(r"^[\s#>*_\-\d.)]+", "", scrubbed)
    for index, match in enumerate(_CAPITAL_RE.finditer(body)):
        word = match.group(0).strip("'’-")
        if word.lower() in _STOP or len(word) < 2:
            continue
        details.append(word)
    seen, unique = set(), []
    for detail in details:
        key = detail.lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(detail)
    return unique


def _detail_present(detail: str, evidence_text: str) -> bool:
    needle = _normalize(detail)
    if needle in evidence_text:
        return True
    if re.fullmatch(r"[\d,.:/-]+", needle):
        bare = re.sub(r"[,]", "", needle)
        return bare in evidence_text.replace(",", "")
    return False


def _content_words(sentence: str) -> list[str]:
    text = CITATION_RE.sub(" ", sentence)
    return [w.lower() for w in _WORD_RE.findall(text) if w.lower() not in _STOP]


def _word_present(word: str, evidence_text: str) -> bool:
    stem = word[:5] if len(word) > 6 else word
    return stem in evidence_text


def _scripts(text: str) -> set[str]:
    scripts = set()
    if _DEVANAGARI_RE.search(text):
        scripts.add("devanagari")
    if _LATIN_RE.search(text):
        scripts.add("latin")
    return scripts


def check_claim(sentence: str, cited: list[str], passages: dict[str, str]) -> dict[str, Any]:
    unknown = [c for c in cited if c not in passages]
    if unknown:
        return {"supported": False, "reason": "cites evidence that was not supplied: " + ", ".join(unknown)}
    evidence_text = _normalize(" ".join(passages[c] for c in cited))
    missing = [d for d in specific_details(sentence) if not _detail_present(d, evidence_text)]
    if missing:
        shown = ", ".join(f"'{m}'" for m in missing[:4])
        return {"supported": False, "reason": f"{shown} not found in {', '.join(cited)}"}
    claim_body = CITATION_RE.sub(" ", sentence)
    if "devanagari" in _scripts(claim_body) and "devanagari" not in _scripts(evidence_text):
        return {"supported": True, "reason": "cross-language claim: identifiers checked only",
                "partial": True}
    words = _content_words(sentence)
    if len(words) >= 3:
        present = sum(_word_present(w, evidence_text) for w in words)
        ratio = present / len(words)
        if ratio < 0.5:
            return {"supported": False,
                    "reason": f"only {present}/{len(words)} key words occur in {', '.join(cited)}"}
    return {"supported": True, "reason": "details found in cited evidence"}


def _llm_entails(sentence: str, passage: str) -> bool | None:
    """Ask the local model for a strict entailment judgement. None = unavailable."""
    if os.environ.get("TRACE_LLM_CLAIM_CHECK", "0") != "1":
        return None
    try:
        import requests
        from modules.llm_engine import MODEL_NAME, OLLAMA_URL
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": "You check facts. Reply with exactly SUPPORTED or NOT_SUPPORTED."},
                {"role": "user", "content": f"PASSAGE:\n{passage[:3000]}\n\nCLAIM:\n{sentence}\n\n"
                                            "Is every part of the claim directly stated in the passage?"},
            ],
            "stream": False, "options": {"temperature": 0, "num_predict": 5},
        }, timeout=60)
        response.raise_for_status()
        verdict = response.json()["message"]["content"].strip().upper()
        return verdict.startswith("SUPPORTED")
    except Exception:
        return None


def verify_answer(answer: str, evidence_results: list[dict[str, Any]]) -> dict[str, Any]:
    passages: dict[str, str] = {}
    for item in evidence_results:
        evidence_id = str(item.get("evidence_id", "")).upper()
        if evidence_id:
            passages[evidence_id] = passages.get(evidence_id, "") + " " + str(
                item.get("snippet") or item.get("text") or ""
            )

    claims: list[dict[str, Any]] = []

    def review(sentence: str) -> str:
        stripped = sentence.strip()
        cited = sorted({c.upper() for c in CITATION_RE.findall(stripped)})
        if not stripped or (_is_heading(stripped) and not cited):
            return sentence
        if not cited:
            details = specific_details(stripped)
            if details and not _REFUSAL_RE.search(stripped):
                claims.append({"sentence": stripped, "cited": [], "supported": False,
                               "reason": "specific details without a citation"})
                return (f"⚠️ *Removed uncited statement with specific details "
                        f"({', '.join(details[:3])}).*")
            return sentence
        result = check_claim(stripped, cited, passages)
        if result["supported"] and not result.get("partial"):
            entails = _llm_entails(stripped, " ".join(passages.get(c, "") for c in cited))
            if entails is False:
                result = {"supported": False,
                          "reason": "local model judged the cited passage does not state this"}
        claims.append({"sentence": stripped, "cited": cited, **result})
        if result["supported"]:
            return sentence
        return f"⚠️ *Removed claim not supported by its citation ({result['reason']}).*"

    lines = []
    for line in answer.splitlines():
        lines.append(" ".join(review(sentence) for sentence in _split_line(line)) if line.strip() else line)
    text = "\n".join(lines)
    checked = [c for c in claims if c["cited"]]
    return {
        "text": text,
        "claims": claims,
        "cited_claims": len(checked),
        "supported": sum(1 for c in checked if c["supported"]),
        "unsupported": sum(1 for c in claims if not c["supported"]),
        "changed": any(not c["supported"] for c in claims),
    }
