
import os
import re

import requests

OLLAMA_BASE_URL = os.environ.get("TRACE_OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/chat"
MODEL_NAME = os.environ.get("TRACE_CHAT_MODEL", "llama3.2:1b")
FOLLOW_UP_PATTERN = re.compile(
    r"\b(he|she|it|they|them|his|her|their|this|that|these|those|"
    r"sender|recipient|same|there|what about|what did|who did)\b",
    re.IGNORECASE,
)


REFUSAL_PATTERN = re.compile(
    r"\b(insufficient evidence|not enough evidence|cannot answer|cannot determine|"
    r"no relevant evidence|unable to answer)\b",
    re.I,
)


def _rejection(evidence_results, output_kind):
    valid_ids = {str(item.get("evidence_id", "")).upper() for item in evidence_results}
    source_list = ", ".join(sorted(identifier for identifier in valid_ids if identifier))
    label = "answer" if output_kind == "answer" else "report draft"
    return (
        f"TRACE AI did not present the generated {label} as a finding because it "
        "did not include valid evidence citations. Review the retrieved source passages directly.\n\n"
        f"Retrieved Evidence IDs: {source_list}"
    )


def verify_generated_text(answer, evidence_results, output_kind="answer"):
    """Return (text to show, verification report).

    Each sentence is checked against the passages it cites (see
    modules.claim_verifier); unsupported sentences are replaced by warnings. If
    no claim survives, the whole output is withheld.
    """
    from modules.claim_verifier import verify_answer

    cited_ids = {value.upper() for value in re.findall(r"\bEV-[A-Z0-9-]+\b", answer, re.I)}
    if not cited_ids:
        if REFUSAL_PATTERN.search(answer):
            return answer, {"claims": [], "cited_claims": 0, "supported": 0, "unsupported": 0,
                            "changed": False, "refusal": True}
        return _rejection(evidence_results, output_kind), {
            "claims": [], "cited_claims": 0, "supported": 0, "unsupported": 0,
            "changed": True, "rejected": "no valid citations"}
    report = verify_answer(answer, evidence_results)
    if report["supported"] == 0:
        report["rejected"] = "no claim was supported by its cited evidence"
        return _rejection(evidence_results, output_kind), report
    return report["text"], report


def enforce_valid_evidence_citations(answer, evidence_results, output_kind="answer"):
    """Backward-compatible wrapper that returns only the checked text."""
    return verify_generated_text(answer, evidence_results, output_kind)[0]


def _chat(messages, *, temperature=0.2, timeout=180, tools=None, num_predict=None):
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature, **({"num_predict": num_predict} if num_predict else {})},
    }
    if tools:
        payload["tools"] = tools
    response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["message"]


def resolve_followup_query(question, conversation_history=None):
    """Resolve an ambiguous reference for retrieval; the rewritten query is not evidence."""
    history = (conversation_history or [])[-6:]
    if not history or not FOLLOW_UP_PATTERN.search(question):
        return question
    history_text = "\n".join(
        f'{message.get("role", "user")}: {str(message.get("content", ""))[:1200]}'
        for message in history
        if message.get("role") in {"user", "assistant"}
    )
    prompt = f"""
Rewrite the investigator's follow-up as one concise, standalone search query.
Use conversation context only to resolve references such as 'he', 'it', or 'the sender'.
Do not answer the question. Do not add events, people, or details that are not in the
conversation. Return only the rewritten query. If the reference cannot be resolved,
return the original question unchanged.

CONVERSATION:
{history_text}

FOLLOW-UP:
{question}
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "messages": [
                    {"role": "system", "content": "Rewrite search queries carefully. Never invent details."},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0, "num_predict": 120},
            },
            timeout=60,
        )
        response.raise_for_status()
        rewritten = response.json()["message"]["content"].strip().strip('"`')
        if not rewritten or len(rewritten) > 500:
            return question
        return rewritten
    except Exception:
        return question


def generate_answer(question, evidence_results, answer_language="English", conversation_history=None,
                    with_report=False):

    if not evidence_results:
        text = (
            "INSUFFICIENT EVIDENCE\n\n"
            "No relevant evidence was retrieved. "
            "TRACE AI cannot answer this question based on the available records."
        )
        return (text, {"claims": [], "refusal": True}) if with_report else text

    context = ""

    for item in evidence_results:
        context += f"""
Evidence ID: {item['evidence_id']}
Filename: {item['filename']}
Relevance Score: {item.get('score', 'N/A')}
Evidence Content:
{item['snippet']}

--------------------------------
"""

    conversation_context = "\n".join(
        f'{message.get("role", "user")}: {str(message.get("content", ""))[:1200]}'
        for message in (conversation_history or [])[-6:]
        if message.get("role") in {"user", "assistant"}
    ) or "No prior conversation."

    prompt = f"""
You are TRACE AI, an evidence-grounded digital investigation assistant.

Analyze the supplied digital evidence carefully.

STRICT RULES:
1. Use ONLY the supplied evidence.
2. Never invent names, dates, events, or details.
3. Separate directly observed facts from interpretations.
4. Cite the Evidence ID for every important finding.
5. Never declare anyone guilty or make unsupported accusations.
6. If evidence is insufficient, explicitly say so.
7. Identify contradictions if different records disagree.
8. Do not treat a relevance score as proof.
9. Do not claim that an event happened unless the evidence supports it.
10. Write the answer in {answer_language}; translate the section headings too.
11. Prior assistant messages are not evidence. Support factual claims only with supplied source passages.
12. Put a bracket citation such as [EV-123ABC] at the end of every factual finding and conclusion. Use only supplied Evidence IDs.

INVESTIGATOR QUESTION:
{question}

PRIOR CONVERSATION (context for resolving references only; it is not evidence):
{conversation_context}

SUPPLIED DIGITAL EVIDENCE:
{context}

Write your response using this structure:

1. INVESTIGATION FINDINGS
Explain what the available evidence shows.

2. CONFIRMED OBSERVATIONS
List only facts directly supported by the supplied records.
Include Evidence IDs.

3. POSSIBLE INTERPRETATIONS
Explain reasonable interpretations separately.
Clearly label them as unverified.

4. EVIDENCE CONTRADICTIONS
Mention conflicting information, or state that none is apparent
in the supplied records.

5. EVIDENCE GAPS AND LIMITATIONS
Explain what cannot be established from the available records.

6. CONCLUSION
Give a short, neutral conclusion based only on the evidence.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a careful digital investigation assistant. "
                            "Never fabricate evidence or conclusions."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=180
        )

        response.raise_for_status()

        answer = response.json()["message"]["content"]
        text, report = verify_generated_text(answer, evidence_results)
        return (text, report) if with_report else text

    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError("Ollama is not running. Please start Ollama and try again.") from exc

    except requests.exceptions.Timeout as exc:
        raise RuntimeError("The local LLM took too long to respond. Try a shorter question.") from exc

    except Exception as exc:
        raise RuntimeError(f"Local LLM request failed: {exc}") from exc


def generate_case_report(case_id, evidence_results, leads=None, activity=None, answer_language="English",
                         with_report=False):
    """Draft a sourced report section set from retrieved records and case notes."""
    if not evidence_results:
        text = "INSUFFICIENT EVIDENCE\n\nNo evidence passages were retrieved for this draft."
        return (text, {"claims": [], "refusal": True}) if with_report else text

    evidence_context = "\n\n".join(
        f"Evidence ID: {item['evidence_id']}\nFilename: {item['filename']}\n"
        f"Source passage:\n{item['snippet'][:1800]}"
        for item in evidence_results[:8]
    )
    lead_context = "\n".join(
        f"{lead.get('lead_id')}: {lead.get('statement')} "
        f"Basis: {lead.get('basis')} Sources: {', '.join(lead.get('supporting_evidence', []))}"
        for lead in (leads or [])[:20]
    ) or "No generated leads supplied."
    activity_context = "\n".join(
        f"{entry['created_at']} {entry['event_type']}: {entry.get('details', {})}"
        for entry in (activity or [])[-30:]
    ) or "No application activity supplied."

    prompt = f"""
Prepare a neutral DRAFT investigation report for case {case_id}.
Write the full report in {answer_language}, including its headings.
Use only supplied source passages for factual claims. Treat lead suggestions as unverified.
Do not infer guilt, intent, identity, or causation. Cite Evidence IDs with every factual finding.
Clearly distinguish source-supported facts, possible interpretations, and missing evidence.
The activity log describes application-recorded actions, not independently verified events.

SUPPLIED EVIDENCE PASSAGES:
{evidence_context}

RULE-GENERATED LEADS (UNVERIFIED):
{lead_context}

APPLICATION ACTIVITY:
{activity_context}

Use headings: Case Scope; Evidence Reviewed; Source-Supported Observations; Unverified Leads;
Limitations and Missing Information; Neutral Summary.
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "messages": [
                    {"role": "system", "content": "Draft cautious, source-cited investigative reports. Never invent facts."},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=240,
        )
        response.raise_for_status()
        draft = response.json()["message"]["content"]
        text, report = verify_generated_text(draft, evidence_results, "report")
        return (text, report) if with_report else text
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError("Ollama is not running. Start the local Ollama service and try again.") from exc
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("The local model took too long to draft this report. Try fewer evidence passages.") from exc
    except Exception as exc:
        raise RuntimeError(f"Local LLM report request failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# Translation (evidence and queries)
# --------------------------------------------------------------------------- #
TRANSLATION_CHUNK = 3000


def detect_script(text):
    """'devanagari', 'latin', or 'mixed'/'unknown' from character counts."""
    deva = len(re.findall(r"[ऀ-ॿ]", text or ""))
    latin = len(re.findall(r"[A-Za-z]", text or ""))
    if not deva and not latin:
        return "unknown"
    if deva and latin and min(deva, latin) / max(deva, latin) > 0.25:
        return "mixed"
    return "devanagari" if deva > latin else "latin"


def translate_query(query, target_language, timeout=30):
    """Translate a short search query. Returns None if the model is unavailable."""
    try:
        reply = _chat([
            {"role": "system", "content": "Translate search queries. Output only the translation, "
                                          "keep names, numbers, IDs, e-mails and IP addresses unchanged."},
            {"role": "user", "content": f"Translate to {target_language}:\n{query}"},
        ], temperature=0, timeout=timeout, num_predict=120)
        text = reply.get("content", "").strip().strip('"`')
        return text if text and len(text) < 500 else None
    except Exception:
        return None


def translate_text(text, target_language, progress=None):
    """Translate evidence text in chunks. Raises RuntimeError if Ollama fails."""
    parts = []
    chunks = [text[i:i + TRANSLATION_CHUNK] for i in range(0, len(text), TRANSLATION_CHUNK)] or [""]
    for index, chunk in enumerate(chunks):
        try:
            reply = _chat([
                {"role": "system", "content": "You are a precise translator for police evidence. Translate "
                 "faithfully. Do not summarize, omit, or add anything. Keep names, numbers, dates, IDs, "
                 "e-mails, phone numbers, URLs and IP addresses exactly as written."},
                {"role": "user", "content": f"Translate into {target_language}:\n\n{chunk}"},
            ], temperature=0, timeout=240)
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError("Ollama is not running. Start Ollama to translate evidence.") from exc
        except Exception as exc:
            raise RuntimeError(f"Translation failed: {exc}") from exc
        parts.append(reply.get("content", ""))
        if progress:
            progress((index + 1) / len(chunks))
    return "\n".join(parts)
