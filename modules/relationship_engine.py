"""Build inspectable relationships from explicit identifiers in evidence."""

from __future__ import annotations

import html
import ipaddress
import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd
from pyvis.network import Network


MAX_RECORDS = 2000
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LABEL_PATTERN = re.compile(
    r"\b(user(?:name)?|account|actor|employee(?:_name)?|sender|recipient|"
    r"device|host|computer|pc|person|full[_ ]?name|email|ip)\s*[:=]\s*"
    r"([^\r\n,;|]{2,100})",
    re.I,
)
IDENTITY_HINTS = (
    "user", "username", "account", "actor", "employee", "sender", "recipient",
    "device", "host", "computer", "pc", "person", "full_name", "email", "ip",
)
TIME_HINTS = ("timestamp", "datetime", "event_time", "date_time", "time", "date")


def _clean(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()


def _entity_type(label: str, value: str) -> str:
    key = label.lower().replace(" ", "_")
    if "email" in key or EMAIL_PATTERN.fullmatch(value):
        return "email"
    if "ip" in key:
        try:
            ipaddress.ip_address(value)
            return "ip address"
        except ValueError:
            pass
    if any(word in key for word in ("device", "host", "computer", "pc")):
        return "device"
    if any(word in key for word in ("person", "employee", "sender", "recipient", "name")):
        return "person / account label"
    return "account / identifier"


def _identities(record: dict[str, Any]) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}

    def add(label: str, raw_value: Any) -> None:
        value = _clean(raw_value).strip(" \t\"'()[]{}")
        if len(value) < 2 or len(value) > 100 or value.lower() in {"nan", "none", "null", "unknown"}:
            return
        normalized = value.casefold()
        found.setdefault(normalized, (value, _entity_type(label, value)))

    for key, raw_value in record.items():
        key_norm = str(key).lower().replace(" ", "_")
        value = _clean(raw_value)
        if not value:
            continue
        if any(
            key_norm == hint or key_norm.endswith("_" + hint) or key_norm.startswith(hint + "_")
            for hint in IDENTITY_HINTS
        ):
            add(key_norm, value)
        for email in EMAIL_PATTERN.findall(value):
            add("email", email)
        for candidate in IP_PATTERN.findall(value):
            try:
                ipaddress.ip_address(candidate)
                add("ip", candidate)
            except ValueError:
                continue
        for label, captured in LABEL_PATTERN.findall(value):
            add(label, captured)
    return found


def _timestamp(record: dict[str, Any]) -> pd.Timestamp | None:
    for key, value in record.items():
        key_norm = str(key).lower().replace(" ", "_")
        if any(key_norm == hint or key_norm.endswith("_" + hint) for hint in TIME_HINTS):
            text = _clean(value)
            # A naive timestamp's timezone is unknown, so it is not used to create
            # temporal links that could imply a false association.
            if not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", text, re.I):
                return None
            parsed = pd.to_datetime(text, errors="coerce", utc=True, format="mixed")
            if pd.notna(parsed):
                return parsed
    return None


def _records_for_item(item: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    path = Path(item.get("original_path", ""))
    suffix = path.suffix.lower()
    if suffix == ".csv":
        frame = pd.read_csv(path, low_memory=False)
        return frame.to_dict(orient="records")[:MAX_RECORDS], len(frame)
    if suffix == ".json":
        with path.open("r", encoding="utf-8-sig") as source:
            payload = json.load(source)
        if isinstance(payload, list):
            rows = [row if isinstance(row, dict) else {"record": row} for row in payload]
            return rows[:MAX_RECORDS], len(rows)
        if isinstance(payload, dict):
            return [payload], 1
        return [{"record": payload}], 1
    return [{"extracted_text": item.get("text", "")}], 1


def build_relationship_graph(
    items: list[dict[str, Any]], temporal_window_minutes: int = 30,
) -> tuple[str, list[dict[str, Any]], dict[str, int]]:
    """Return an inlined PyVis HTML graph, inspectable record catalog, and counts."""
    graph = nx.Graph()
    catalog: list[dict[str, Any]] = []
    temporal_records: list[tuple[pd.Timestamp, int, str]] = []
    entity_to_records: dict[str, list[int]] = {}
    truncated = 0

    for item in items:
        try:
            rows, total_count = _records_for_item(item)
        except Exception:
            continue
        truncated += max(0, total_count - len(rows))
        for source_row, record in enumerate(rows, start=1):
            if len(catalog) >= MAX_RECORDS:
                truncated += 1
                continue
            record_key = f"record:{item['evidence_id']}:{source_row}"
            identities = _identities(record)
            timestamp = _timestamp(record)
            view = {str(key): _clean(value) for key, value in record.items()}
            catalog.append({
                "record_key": record_key,
                "evidence_id": item["evidence_id"],
                "filename": item["filename"],
                "row_number": source_row,
                "timestamp": timestamp.isoformat() if timestamp is not None else "",
                "identities": sorted(identities),
                "record": view,
            })
            title = html.escape(
                f"{item['evidence_id']} · {item['filename']} · record {source_row}"
            )
            graph.add_node(record_key, label=f"{item['evidence_id']} #{source_row}",
                           title=title, group="evidence record", shape="box")
            for normalized, (display, kind) in identities.items():
                entity_key = f"entity:{normalized}"
                graph.add_node(entity_key, label=html.escape(display), title=html.escape(f"{kind}: {display}"), group=kind)
                graph.add_edge(record_key, entity_key, label="observed in", title="Explicit identifier in this source record")
                entity_to_records.setdefault(entity_key, []).append(len(catalog) - 1)
            if timestamp is not None:
                temporal_records.append((timestamp, len(catalog) - 1, item["evidence_id"]))

    temporal_records.sort(key=lambda value: value[0])
    window = timedelta(minutes=temporal_window_minutes)
    for position, (timestamp, catalog_index, evidence_id) in enumerate(temporal_records):
        linked = 0
        for other_time, other_index, other_evidence_id in temporal_records[position + 1:]:
            delta = other_time - timestamp
            if delta > window:
                break
            if evidence_id == other_evidence_id or linked >= 10:
                continue
            first_key = catalog[catalog_index]["record_key"]
            second_key = catalog[other_index]["record_key"]
            graph.add_edge(
                first_key, second_key,
                label="near in time",
                title=f"Timezone-explicit timestamps are {int(delta.total_seconds() // 60)} minute(s) apart; proximity does not establish a relationship.",
                color="#d97706", dashes=True,
            )
            linked += 1

    if graph.number_of_nodes() == 0:
        return "", catalog, {"records": 0, "entities": 0, "temporal_links": 0, "truncated": truncated}

    network = Network(height="620px", width="100%", directed=False, cdn_resources="in_line")
    network.from_nx(graph)
    network.set_options("""
    {
      "nodes": {"font": {"size": 14}, "scaling": {"label": {"enabled": true, "min": 12, "max": 24}}},
      "edges": {"font": {"size": 10, "align": "middle"}, "smooth": {"type": "dynamic"}},
      "physics": {"stabilization": {"iterations": 150}, "barnesHut": {"gravitationalConstant": -3200}}
    }
    """)
    html_graph = network.generate_html()
    return html_graph, catalog, {
        "records": len(catalog),
        "entities": sum(1 for node, data in graph.nodes(data=True) if str(node).startswith("entity:")),
        "temporal_links": sum(1 for _, _, data in graph.edges(data=True) if data.get("label") == "near in time"),
        "truncated": truncated,
    }


def supporting_records(catalog: list[dict[str, Any]], entity_key: str) -> list[dict[str, Any]]:
    return [record for record in catalog if entity_key in record["identities"]]


def render_relationship_graph(catalog: list[dict[str, Any]], temporal_window_minutes: int = 30) -> str:
    """Rebuild the interactive view from persisted, JSON-safe graph records."""
    graph = nx.Graph()
    temporal_records: list[tuple[pd.Timestamp, dict[str, Any]]] = []
    for record in catalog:
        record_key = record["record_key"]
        label = f'{record["evidence_id"]} #{record["row_number"]}'
        graph.add_node(
            record_key, label=label,
            title=html.escape(f'{record["evidence_id"]} · {record["filename"]} · record {record["row_number"]}'),
            group="evidence record", shape="box",
        )
        for identifier in record["identities"]:
            entity_key = f"entity:{identifier}"
            graph.add_node(entity_key, label=html.escape(identifier), title=html.escape(identifier), group="identifier")
            graph.add_edge(record_key, entity_key, label="observed in", title="Explicit identifier in this source record")
        if record.get("timestamp"):
            parsed = pd.to_datetime(record["timestamp"], errors="coerce", utc=True, format="mixed")
            if pd.notna(parsed):
                temporal_records.append((parsed, record))

    temporal_records.sort(key=lambda entry: entry[0])
    window = timedelta(minutes=temporal_window_minutes)
    for position, (timestamp, record) in enumerate(temporal_records):
        linked = 0
        for other_time, other in temporal_records[position + 1:]:
            delta = other_time - timestamp
            if delta > window:
                break
            if record["evidence_id"] == other["evidence_id"] or linked >= 10:
                continue
            graph.add_edge(
                record["record_key"], other["record_key"],
                label="near in time", title=(
                    f"Timezone-explicit timestamps are "
                    f"{int(delta.total_seconds() // 60)} minute(s) apart; proximity does not establish a relationship."
                ), color="#d97706", dashes=True,
            )
            linked += 1

    if not graph.number_of_nodes():
        return ""
    network = Network(height="620px", width="100%", directed=False, cdn_resources="in_line")
    network.from_nx(graph)
    network.set_options("""
    {"nodes":{"font":{"size":14}},"edges":{"font":{"size":10,"align":"middle"},"smooth":{"type":"dynamic"}},
     "physics":{"stabilization":{"iterations":150},"barnesHut":{"gravitationalConstant":-3200}}}
    """)
    return network.generate_html()

