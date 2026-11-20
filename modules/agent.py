"""Tool-using investigation agent (local Ollama function calling).

The model can decide which read-only tools to call — search passages, read a
specific evidence item, filter the timeline, filter structured records, look at
anomaly flags and leads — and loop until it can answer.  Safety properties:

* Every tool is **read-only** and bound to the single active case passed in by
  the app after the permission check; the model cannot choose another case.
* Every piece of text a tool returns is added to the citation pool; the final
  answer is checked claim-by-claim against that pool (modules.claim_verifier).
* The loop is capped (``MAX_STEPS``) and every tool call is recorded and shown
  to the investigator, so the reasoning path is auditable.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Callable

from modules import database

MAX_STEPS = 6
MAX_TOOL_CHARS = 6000

TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "search_evidence",
        "description": "Search this case's evidence passages (keyword + semantic). Returns passages with evidence IDs.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "What to look for"},
            "top_k": {"type": "integer", "description": "Number of passages (1-10)"},
        }, "required": ["query"]},
    }},
    {"type": "function", "function": {
        "name": "list_evidence",
        "description": "List evidence items in this case with ID, filename, type and extraction status.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "read_evidence",
        "description": "Read part of one evidence item's extracted text.",
        "parameters": {"type": "object", "properties": {
            "evidence_id": {"type": "string"},
            "offset": {"type": "integer", "description": "Character offset (default 0)"},
            "length": {"type": "integer", "description": "Characters to read (max 4000)"},
        }, "required": ["evidence_id"]},
    }},
    {"type": "function", "function": {
        "name": "query_timeline",
        "description": "Filter timestamped events (logs, EVTX, PCAP, filesystem, CSV/JSON) by UTC time range and/or keyword.",
        "parameters": {"type": "object", "properties": {
            "start": {"type": "string", "description": "ISO 8601 start, e.g. 2024-03-01T00:00:00"},
            "end": {"type": "string", "description": "ISO 8601 end"},
            "keyword": {"type": "string"},
            "evidence_id": {"type": "string"},
            "limit": {"type": "integer", "description": "Max events (default 50)"},
        }},
    }},
    {"type": "function", "function": {
        "name": "filter_records",
        "description": "Filter rows of a CSV/JSON evidence item where a field equals or contains a value.",
        "parameters": {"type": "object", "properties": {
            "evidence_id": {"type": "string"},
            "field": {"type": "string"},
            "value": {"type": "string"},
            "match": {"type": "string", "enum": ["equals", "contains"]},
            "limit": {"type": "integer"},
        }, "required": ["evidence_id", "field", "value"]},
    }},
    {"type": "function", "function": {
        "name": "get_anomalies",
        "description": "Records flagged by the last anomaly review (rule and statistical flags).",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_leads",
        "description": "Rule-generated investigative leads and their review status (unverified).",
        "parameters": {"type": "object", "properties": {}},
    }},
]


def _parse_records(item: dict[str, Any]) -> list[dict[str, Any]]:
    text = item.get("text") or ""
    if item.get("file_type") == "csv":
        return list(csv.DictReader(io.StringIO(text)))
    if item.get("file_type") == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    data = value
                    break
            else:
                data = [data]
        return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []
    return []


class CaseTools:
    """Read-only tools bound to one case. Collects every returned source."""

    def __init__(self, case_id: str, evidence: list[dict[str, Any]],
                 search: Callable[[str, list[dict[str, Any]], int], list[dict[str, Any]]]):
        self.case_id = case_id
        self.evidence = {item["evidence_id"]: item for item in evidence}
        self._search = search
        self.sources: list[dict[str, Any]] = []
        self.steps: list[dict[str, Any]] = []

    def _cite(self, evidence_id: str, snippet: str, label: str = "") -> None:
        item = self.evidence.get(evidence_id, {})
        self.sources.append({
            "evidence_id": evidence_id, "filename": item.get("filename", ""),
            "snippet": snippet, "score": 0.0, "chunk_id": label or "tool",
            "retrieval_mode": "agent tool",
        })

    def run(self, name: str, arguments: dict[str, Any]) -> str:
        handler = getattr(self, f"tool_{name}", None)
        if handler is None:
            result: Any = {"error": f"Unknown tool {name}"}
        else:
            try:
                result = handler(**{k: v for k, v in (arguments or {}).items() if v not in (None, "")})
            except TypeError as exc:
                result = {"error": f"Bad arguments: {exc}"}
            except Exception as exc:  # tool errors are reported to the model, not raised
                result = {"error": str(exc)}
        text = json.dumps(result, ensure_ascii=False, default=str)
        if len(text) > MAX_TOOL_CHARS:
            text = text[:MAX_TOOL_CHARS] + ' …"[truncated]"'
        self.steps.append({"tool": name, "arguments": arguments,
                           "summary": _summarize(result)})
        return text

    # -- tools ------------------------------------------------------------
    def tool_search_evidence(self, query: str, top_k: int = 5):
        results = self._search(str(query), list(self.evidence.values()), max(1, min(int(top_k), 10)))
        for row in results:
            self._cite(row["evidence_id"], row["snippet"], str(row.get("chunk_id", "")))
        return [{"evidence_id": r["evidence_id"], "filename": r["filename"], "passage": r["snippet"]}
                for r in results]

    def tool_list_evidence(self):
        return [{"evidence_id": i["evidence_id"], "filename": i["filename"], "type": i["file_type"],
                 "status": i["extraction_status"], "characters": len(i.get("text") or "")}
                for i in self.evidence.values()]

    def tool_read_evidence(self, evidence_id: str, offset: int = 0, length: int = 2000):
        evidence_id = str(evidence_id).upper()
        item = self.evidence.get(evidence_id)
        if not item:
            return {"error": "No such evidence in this case."}
        offset = max(0, int(offset))
        length = max(100, min(int(length), 4000))
        text = (item.get("text") or "")[offset:offset + length]
        self._cite(evidence_id, text, f"chars {offset}-{offset + len(text)}")
        return {"evidence_id": evidence_id, "filename": item["filename"], "offset": offset,
                "text": text, "total_characters": len(item.get("text") or "")}

    def tool_query_timeline(self, start: str = "", end: str = "", keyword: str = "",
                            evidence_id: str = "", limit: int = 50):
        events = database.query_timeline(self.case_id, start or None, end or None, keyword or None,
                                         str(evidence_id).upper() or None, max(1, min(int(limit), 200)))
        for event in events:
            self._cite(event["evidence_id"], f'{event["ts"]} {event["summary"]} '
                       + json.dumps(event["fields"], ensure_ascii=False), "timeline")
        return [{"evidence_id": e["evidence_id"], "time": e["ts"], "event": e["summary"],
                 "fields": e["fields"]} for e in events]

    def tool_filter_records(self, evidence_id: str, field: str, value: str,
                            match: str = "contains", limit: int = 25):
        evidence_id = str(evidence_id).upper()
        item = self.evidence.get(evidence_id)
        if not item:
            return {"error": "No such evidence in this case."}
        rows = _parse_records(item)
        if not rows:
            return {"error": "This evidence has no CSV/JSON records."}
        needle = str(value).lower()
        keys = {k.lower(): k for k in rows[0].keys()}
        key = keys.get(str(field).lower())
        if key is None:
            return {"error": f"Field not found. Available: {', '.join(list(rows[0].keys())[:30])}"}
        hits = []
        for number, row in enumerate(rows, start=1):
            cell = str(row.get(key, "")).lower()
            if (cell == needle) if match == "equals" else (needle in cell):
                hits.append({"row": number, **row})
                if len(hits) >= max(1, min(int(limit), 100)):
                    break
        for hit in hits:
            self._cite(evidence_id, json.dumps(hit, ensure_ascii=False), f'row {hit["row"]}')
        return {"evidence_id": evidence_id, "matches": hits, "rows_scanned": len(rows)}

    def tool_get_anomalies(self):
        result = database.load_analysis_result(self.case_id, "anomaly") or {}
        flagged = result.get("flagged", [])[:30]
        for row in flagged:
            self._cite(row["evidence_id"], json.dumps(row.get("original_record", {}), ensure_ascii=False),
                       f'row {row.get("row_number")}')
        return [{"evidence_id": r["evidence_id"], "row": r.get("row_number"),
                 "reasons": r.get("reasons"), "record": r.get("original_record")} for r in flagged] \
            or {"note": "No anomaly review has been run, or nothing was flagged."}

    def tool_get_leads(self):
        return [{"lead_id": lead["lead_id"], "statement": lead.get("statement"), "status": lead["status"],
                 "supporting_evidence": lead.get("supporting_evidence")}
                for lead in database.list_leads(self.case_id)[:30]] or {"note": "No leads yet."}


def _summarize(result: Any) -> str:
    if isinstance(result, dict) and "error" in result:
        return "error: " + str(result["error"])[:200]
    if isinstance(result, dict) and "matches" in result:
        return f'{len(result["matches"])} matching rows'
    if isinstance(result, list):
        return f"{len(result)} result(s)"
    if isinstance(result, dict) and "text" in result:
        return f'{len(result["text"])} characters read'
    return "ok"


AGENT_SYSTEM_PROMPT = """You are TRACE AI, a careful digital-forensics investigation assistant.
You can call tools to look up evidence in the current case. Plan briefly, call tools to gather
facts (search, read, timeline, record filters), then answer.

Rules:
- Use ONLY information returned by tools. Never invent names, times, numbers or events.
- End every factual sentence with the bracketed evidence ID it came from, e.g. [EV-1A2B3C4D5E6F].
- Separate confirmed observations from interpretations; label interpretations as unverified.
- If the tools do not return enough information, say "insufficient evidence" for that point.
- Never state or imply guilt.
- Write the final answer in {language}."""


def run_agent(question: str, case_id: str, evidence: list[dict[str, Any]],
              search: Callable, answer_language: str = "English",
              history: list[dict[str, Any]] | None = None,
              chat: Callable | None = None) -> dict[str, Any]:
    """Run the tool loop. ``chat(messages, tools=...)`` returns an Ollama message dict."""
    from modules import llm_engine

    chat = chat or (lambda messages, tools=None: llm_engine._chat(messages, tools=tools, temperature=0.1,
                                                                 timeout=240))
    tools = CaseTools(case_id, evidence, search)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT.format(language=answer_language)},
    ]
    for message in (history or [])[-6:]:
        if message.get("role") in {"user", "assistant"}:
            messages.append({"role": message["role"], "content": str(message.get("content", ""))[:1500]})
    messages.append({"role": "user", "content": question})

    final = ""
    for _ in range(MAX_STEPS):
        reply = chat(messages, tools=TOOL_SPECS)
        calls = reply.get("tool_calls") or []
        if not calls:
            final = reply.get("content", "")
            break
        messages.append({"role": "assistant", "content": reply.get("content", ""), "tool_calls": calls})
        for call in calls:
            function = call.get("function", {})
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            output = tools.run(function.get("name", ""), arguments)
            messages.append({"role": "tool", "content": output, "tool_name": function.get("name", ""),
                             "name": function.get("name", "")})
    else:
        messages.append({"role": "user", "content": "Tool budget reached. Answer now using only the tool results above."})
        final = chat(messages, tools=None).get("content", "")

    if not tools.sources:
        text, report = llm_engine.verify_generated_text(final, [])
    else:
        text, report = llm_engine.verify_generated_text(final, tools.sources)
    return {"answer": text, "raw_answer": final, "sources": _dedupe(tools.sources),
            "steps": tools.steps, "verification": report}


def _dedupe(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen, unique = set(), []
    for source in sources:
        key = (source["evidence_id"], source["snippet"][:200])
        if key not in seen:
            seen.add(key)
            unique.append(source)
    return unique[:40]
