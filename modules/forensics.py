"""Parsers for forensic artefact formats (no Streamlit dependencies).

Every public parser returns a dict:
    {"text": str, "timeline": list[dict], "metadata": dict, "status": str}
with metadata["warnings"] listing anything that was skipped or truncated.
Parsers raise ValueError only when the input is clearly not the claimed
format; damaged-but-recognisable inputs yield partial results.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

MAX_TEXT_CHARS = 5_000_000
MAX_TIMELINE = 50_000
MAX_DISK_ENTRIES = 100_000
DISK_TEXT_FILE_LIMIT = 1_000_000
DISK_TEXT_TOTAL_LIMIT = 2_000_000
DISK_TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".ini"}
MEMORY_SAMPLE_BYTES = 256 * 1024 * 1024
BLOCK_SIZE = 4 * 1024 * 1024

EVTX_EXTENSIONS = {".evtx"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
DISK_EXTENSIONS = {".e01", ".ex01", ".dd", ".raw", ".img", ".001"}
MEMORY_EXTENSIONS = {".mem", ".vmem", ".lime", ".dmp"}

Progress = Callable[[float, str], None] | None
Source = bytes | str | Path


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

class CappedText:
    """Accumulates lines up to a character budget."""

    def __init__(self, limit: int = MAX_TEXT_CHARS):
        self.limit = limit
        self.parts: list[str] = []
        self.size = 0
        self.truncated = False
        self.dropped_lines = 0

    def add(self, line: str) -> bool:
        if self.truncated:
            self.dropped_lines += 1
            return False
        if self.size + len(line) + 1 > self.limit:
            self.truncated = True
            self.dropped_lines += 1
            return False
        self.parts.append(line)
        self.size += len(line) + 1
        return True

    def render(self) -> str:
        text = "\n".join(self.parts)
        if self.truncated:
            text += (
                f"\n[truncated: text limit of {self.limit:,} characters reached; "
                f"{self.dropped_lines:,} further lines omitted]"
            )
        return text


class Timeline:
    def __init__(self, limit: int = MAX_TIMELINE):
        self.limit = limit
        self.entries: list[dict] = []
        self.dropped = 0

    def add(self, timestamp: str | None, summary: str, source: str, fields: dict) -> None:
        if not timestamp:
            return
        if len(self.entries) >= self.limit:
            self.dropped += 1
            return
        self.entries.append({
            "timestamp": timestamp,
            "summary": summary[:500],
            "source": source,
            "fields": fields,
        })


def iso_utc(value) -> str | None:
    """Convert epoch seconds or an aware/naive-UTC datetime to ISO 8601 Z."""
    if value is None:
        return None
    try:
        if isinstance(value, datetime):
            moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        else:
            number = float(value)
            if number <= 0:
                return None
            moment = datetime.fromtimestamp(number, tz=timezone.utc)
        moment = moment.astimezone(timezone.utc)
        if moment.year < 1971 or moment.year > 2200:
            return None
        return moment.isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _notify(progress: Progress, fraction: float, message: str) -> None:
    if progress:
        try:
            progress(max(0.0, min(1.0, fraction)), message)
        except Exception:
            pass


@contextmanager
def as_path(source: Source, suffix: str) -> Iterator[Path]:
    """Yield a filesystem path for bytes or path input (temp file for bytes)."""
    if isinstance(source, (str, Path)):
        yield Path(source)
        return
    handle = tempfile.NamedTemporaryFile(prefix="trace_", suffix=suffix, delete=False)
    try:
        handle.write(source)
        handle.close()
        yield Path(handle.name)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def _result(text: CappedText, timeline: Timeline, metadata: dict, status: str,
            warnings: list[str]) -> dict:
    if text.truncated:
        warnings.append(f"Text truncated at {text.limit:,} characters")
        metadata["text_truncated"] = True
    if timeline.dropped:
        warnings.append(f"Timeline capped at {timeline.limit:,} entries "
                        f"({timeline.dropped:,} more omitted)")
        metadata["timeline_truncated"] = True
    metadata["warnings"] = warnings
    metadata["timeline_entries"] = len(timeline.entries)
    return {
        "text": text.render(),
        "timeline": timeline.entries,
        "metadata": metadata,
        "status": status,
    }


# --------------------------------------------------------------------------
# EVTX
# --------------------------------------------------------------------------

_EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_EVTX_KEY_FIELDS = (
    "TargetUserName", "SubjectUserName", "TargetDomainName", "IpAddress",
    "IpPort", "WorkstationName", "LogonType", "ProcessName", "NewProcessName",
    "CommandLine", "ServiceName", "ImagePath", "ObjectName", "ShareName",
)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _parse_evtx_time(value: str) -> str | None:
    """Parse EVTX SystemTime ('2024-01-01 10:00:00.123456+00:00' or '...Z')."""
    if not value:
        return None
    match = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$",
                     value.strip())
    if not match:
        return None
    date, clock, fraction, zone = match.groups()
    cleaned = f"{date}T{clock}"
    if fraction:
        cleaned += "." + fraction[:6].ljust(6, "0")
    cleaned += "+00:00" if not zone or zone == "Z" else zone
    try:
        return iso_utc(datetime.fromisoformat(cleaned))
    except ValueError:
        return None


def _evtx_record_fields(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find(f"{_EVT_NS}System")
    fields: dict = {}
    if system is not None:
        for child in system:
            tag = _strip_ns(child.tag)
            if tag == "EventID":
                fields["EventID"] = (child.text or "").strip()
            elif tag == "TimeCreated":
                fields["TimeCreated"] = _parse_evtx_time(child.get("SystemTime", ""))
            elif tag == "Computer":
                fields["Computer"] = (child.text or "").strip()
            elif tag == "Channel":
                fields["Channel"] = (child.text or "").strip()
            elif tag == "Provider":
                fields["Provider"] = child.get("Name") or child.get("EventSourceName") or ""
            elif tag == "EventRecordID":
                fields["EventRecordID"] = (child.text or "").strip()
    data: dict = {}
    for section in ("EventData", "UserData"):
        node = root.find(f"{_EVT_NS}{section}")
        if node is None:
            continue
        unnamed = 0
        for element in node.iter():
            if element is node:
                continue
            tag = _strip_ns(element.tag)
            value = (element.text or "").strip()
            if tag == "Data":
                name = element.get("Name")
                if not name:
                    unnamed += 1
                    name = f"Data{unnamed}"
                data[name] = value
            elif value and len(element) == 0:
                data[tag] = value
    fields["data"] = data
    return fields


def parse_evtx(source: Source, progress: Progress = None) -> dict:
    header = _read_head(source, 8)
    if not header.startswith(b"ElfFile"):
        raise ValueError("Not a Windows EVTX log (missing 'ElfFile' header)")
    from Evtx.Evtx import Evtx

    text = CappedText()
    timeline = Timeline()
    warnings: list[str] = []
    event_ids: Counter = Counter()
    channels: Counter = Counter()
    computers: Counter = Counter()
    records = 0
    bad_records = 0
    first = last = None

    with as_path(source, ".evtx") as path:
        try:
            with Evtx(str(path)) as log:
                iterator = log.records()
                while True:
                    try:
                        record = next(iterator)
                    except StopIteration:
                        break
                    except Exception as exc:
                        warnings.append(f"Stopped reading damaged EVTX chunk: {exc}")
                        break
                    try:
                        fields = _evtx_record_fields(record.xml())
                    except Exception:
                        bad_records += 1
                        continue
                    records += 1
                    if records % 2000 == 0:
                        _notify(progress, 0.5, f"EVTX: {records:,} records parsed")
                    stamp = fields.get("TimeCreated")
                    if not stamp:
                        try:
                            stamp = iso_utc(record.timestamp())
                        except Exception:
                            stamp = None
                    event_id = fields.get("EventID", "")
                    event_ids[event_id] += 1
                    channels[fields.get("Channel", "")] += 1
                    computers[fields.get("Computer", "")] += 1
                    if stamp:
                        first = min(first, stamp) if first else stamp
                        last = max(last, stamp) if last else stamp
                    data = fields["data"]
                    parts = [stamp or "(no time)", f"EventID={event_id}"]
                    for key in ("Channel", "Provider", "Computer"):
                        if fields.get(key):
                            parts.append(f"{key}={fields[key]}")
                    for key, value in data.items():
                        if value and value != "-":
                            parts.append(f"{key}={value}")
                    text.add(" ".join(parts)[:4000])
                    key_fields = {
                        "EventID": event_id,
                        "Computer": fields.get("Computer", ""),
                        "Channel": fields.get("Channel", ""),
                        "Provider": fields.get("Provider", ""),
                    }
                    for key in _EVTX_KEY_FIELDS:
                        if data.get(key) and data[key] != "-":
                            key_fields[key] = data[key][:300]
                    summary_bits = [f"EventID {event_id}", fields.get("Provider", "")]
                    for key in ("TargetUserName", "IpAddress", "ProcessName", "NewProcessName"):
                        if key in key_fields:
                            summary_bits.append(f"{key}={key_fields[key]}")
                    timeline.add(stamp, " ".join(b for b in summary_bits if b), "evtx", key_fields)
        except ValueError:
            raise
        except Exception as exc:
            if records == 0:
                raise ValueError(f"Unable to parse EVTX file: {exc}") from exc
            warnings.append(f"EVTX parsing stopped early: {exc}")

    if bad_records:
        warnings.append(f"{bad_records:,} records could not be decoded")
    metadata = {
        "format": "evtx",
        "record_count": records,
        "event_id_counts": dict(event_ids.most_common(20)),
        "channels": dict(channels.most_common(10)),
        "computers": dict(computers.most_common(10)),
        "first_event": first,
        "last_event": last,
    }
    return _result(text, timeline, metadata, f"EVTX parsed: {records:,} records", warnings)


def _read_head(source: Source, size: int) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source[:size])
    with open(source, "rb") as handle:
        return handle.read(size)


# --------------------------------------------------------------------------
# PCAP / PCAPNG
# --------------------------------------------------------------------------

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"CONNECT ", b"TRACE ")
_IP_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}


def _ip_to_str(raw: bytes) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw.hex()


def _extract_ip(buf: bytes, linktype: int):
    import dpkt

    if linktype in (1,):  # Ethernet
        frame = dpkt.ethernet.Ethernet(buf)
        return frame.data if isinstance(frame.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype == 113:  # Linux cooked SLL
        frame = dpkt.sll.SLL(buf)
        return frame.data if isinstance(frame.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype == 276:  # Linux cooked SLL2: 20-byte header, protocol first
        if len(buf) < 20:
            return None
        proto = struct.unpack("!H", buf[:2])[0]
        payload = buf[20:]
        if proto == 0x0800:
            return dpkt.ip.IP(payload)
        if proto == 0x86DD:
            return dpkt.ip6.IP6(payload)
        return None
    if linktype in (0, 108):  # BSD loopback / OpenBSD loop
        payload = buf[4:]
    elif linktype in (12, 14, 101, 228, 229):  # raw IP
        payload = buf
    else:
        return None
    if not payload:
        return None
    version = payload[0] >> 4
    if version == 4:
        return dpkt.ip.IP(payload)
    if version == 6:
        return dpkt.ip6.IP6(payload)
    return None


def _tls_sni(payload: bytes) -> str | None:
    """Best-effort Server Name Indication from a TLS ClientHello."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # record hdr, handshake hdr, version, random
        session_len = payload[pos]
        pos += 1 + session_len
        cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0:
                body = payload[pos:pos + ext_len]
                cursor = 2
                while cursor + 3 <= len(body):
                    name_type = body[cursor]
                    name_len = struct.unpack("!H", body[cursor + 1:cursor + 3])[0]
                    name = body[cursor + 3:cursor + 3 + name_len]
                    if name_type == 0 and name:
                        return name.decode("ascii", errors="replace")
                    cursor += 3 + name_len
                return None
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


def _http_request(payload: bytes) -> dict | None:
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return {
        "method": parts[0],
        "path": parts[1][:1000],
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", "")[:300],
    }


def _dns_events(payload: bytes) -> list[dict]:
    import dpkt

    message = dpkt.dns.DNS(payload)
    events = []
    if message.qr == dpkt.dns.DNS_Q:
        for question in message.qd:
            events.append({"kind": "query", "name": question.name,
                           "qtype": _dns_type(question.type)})
    else:
        answers = []
        for answer in message.an:
            rtype = _dns_type(answer.type)
            if answer.type == dpkt.dns.DNS_A:
                value = socket.inet_ntop(socket.AF_INET, answer.rdata)
            elif answer.type == dpkt.dns.DNS_AAAA:
                value = socket.inet_ntop(socket.AF_INET6, answer.rdata)
            elif answer.type == dpkt.dns.DNS_CNAME:
                value = answer.cname
            elif answer.type == dpkt.dns.DNS_MX:
                value = answer.mxname
            elif answer.type == dpkt.dns.DNS_TXT:
                value = " ".join(t.decode("utf-8", "replace") if isinstance(t, bytes) else str(t)
                                 for t in getattr(answer, "text", []))
            else:
                value = answer.rdata.hex()[:80] if answer.rdata else ""
            answers.append(f"{rtype} {value}")
        name = message.qd[0].name if message.qd else (message.an[0].name if message.an else "")
        events.append({"kind": "answer", "name": name, "answers": answers,
                       "rcode": message.rcode})
    return events


def _dns_type(code: int) -> str:
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
            16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}.get(code, str(code))


class _ClassicPcapReader:
    """Minimal libpcap reader that reports truncated trailing records."""

    def __init__(self, handle):
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError("file shorter than the 24-byte pcap header")
        magic = header[:4]
        self._endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        self._nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        self._linktype = struct.unpack(self._endian + "I", header[20:24])[0] & 0x0FFFFFFF
        self._handle = handle

    def datalink(self) -> int:
        return self._linktype

    def __iter__(self):
        divisor = 1e9 if self._nano else 1e6
        while True:
            header = self._handle.read(16)
            if not header:
                return
            if len(header) < 16:
                raise ValueError("truncated packet record header")
            seconds, fraction, caplen, _length = struct.unpack(self._endian + "IIII", header)
            if caplen > 256 * 1024 * 1024:
                raise ValueError(f"implausible captured length {caplen}")
            data = self._handle.read(caplen)
            if len(data) < caplen:
                raise ValueError(f"truncated packet data ({len(data)} of {caplen} bytes)")
            yield seconds + fraction / divisor, data


def parse_pcap(source: Source, progress: Progress = None) -> dict:
    import dpkt

    head = _read_head(source, 4)
    if head in _PCAP_MAGICS:
        reader_cls, kind = _ClassicPcapReader, "pcap"
    elif head == _PCAPNG_MAGIC:
        reader_cls, kind = dpkt.pcapng.Reader, "pcapng"
    else:
        raise ValueError("Not a pcap/pcapng capture (unrecognised file magic)")

    warnings: list[str] = []
    timeline = Timeline()
    flows: dict[tuple, dict] = {}
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    dns_lines: list[str] = []
    http_lines: list[str] = []
    tls_lines: list[str] = []
    packets = 0
    non_ip = 0
    decode_errors = 0
    first_ts = last_ts = None

    handle = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else open(source, "rb")
    try:
        try:
            reader = reader_cls(handle)
        except Exception as exc:
            raise ValueError(f"Unable to read {kind} header: {exc}") from exc
        linktype = reader.datalink()
        iterator = iter(reader)
        while True:
            try:
                ts, buf = next(iterator)
            except StopIteration:
                break
            except Exception as exc:
                warnings.append(f"Capture ends with a truncated/damaged record: {exc}")
                break
            packets += 1
            if packets % 50_000 == 0:
                _notify(progress, 0.5, f"PCAP: {packets:,} packets read")
            ts = float(ts)
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            try:
                ip = _extract_ip(buf, linktype)
            except Exception:
                decode_errors += 1
                continue
            if ip is None:
                non_ip += 1
                protocols["non-IP"] += 1
                continue
            stamp = iso_utc(ts)
            src, dst = _ip_to_str(ip.src), _ip_to_str(ip.dst)
            proto_num = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
            proto = _IP_PROTOS.get(proto_num, str(proto_num))
            protocols[proto] += 1
            size = len(buf)
            talkers[src] += size
            layer4 = ip.data
            sport = dport = 0
            payload = b""
            if isinstance(layer4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                sport, dport = layer4.sport, layer4.dport
                payload = bytes(layer4.data)
            key = (proto, src, sport, dst, dport)
            reverse = (proto, dst, dport, src, sport)
            flow_key = reverse if reverse in flows else key
            flow = flows.get(flow_key)
            if flow is None:
                if len(flows) < 200_000:
                    flow = flows[flow_key] = {"packets": 0, "bytes": 0,
                                              "first": ts, "last": ts}
                    timeline.add(stamp, f"Flow start {proto} {src}:{sport} -> {dst}:{dport}",
                                 "pcap", {"event": "flow_start", "proto": proto, "src": src,
                                          "sport": sport, "dst": dst, "dport": dport})
            if flow is not None:
                flow["packets"] += 1
                flow["bytes"] += size
                flow["last"] = max(flow["last"], ts)
            if not payload:
                continue
            try:
                if proto == "UDP" and 53 in (sport, dport):
                    for event in _dns_events(payload):
                        if event["kind"] == "query":
                            line = f"{stamp} DNS query {event['name']} ({event['qtype']}) from {src}"
                            fields = {"event": "dns_query", "query": event["name"],
                                      "qtype": event["qtype"], "src": src, "dst": dst}
                        else:
                            answers = ", ".join(event["answers"]) or f"rcode={event['rcode']}"
                            line = f"{stamp} DNS answer {event['name']} -> {answers}"
                            fields = {"event": "dns_answer", "query": event["name"],
                                      "answers": event["answers"][:10], "server": src}
                        if len(dns_lines) < 100_000:
                            dns_lines.append(line)
                        timeline.add(stamp, line.split(" ", 1)[1], "pcap", fields)
                elif proto == "TCP":
                    request = _http_request(payload)
                    if request:
                        line = (f"{stamp} HTTP {request['method']} http://{request['host']}"
                                f"{request['path']} from {src}:{sport} to {dst}:{dport}")
                        if request["user_agent"]:
                            line += f" UA={request['user_agent']}"
                        if len(http_lines) < 100_000:
                            http_lines.append(line)
                        timeline.add(stamp, f"HTTP {request['method']} {request['host']}{request['path']}"[:300],
                                     "pcap", {"event": "http_request", "src": src, "dst": dst,
                                              "dport": dport, **request})
                    else:
                        sni = _tls_sni(payload)
                        if sni:
                            line = f"{stamp} TLS ClientHello SNI={sni} {src}:{sport} -> {dst}:{dport}"
                            if len(tls_lines) < 100_000:
                                tls_lines.append(line)
                            timeline.add(stamp, f"TLS SNI {sni}", "pcap",
                                         {"event": "tls_sni", "sni": sni, "src": src,
                                          "dst": dst, "dport": dport})
            except Exception:
                decode_errors += 1
    finally:
        handle.close()

    if packets == 0:
        warnings.append("Capture contains no packets")
    if decode_errors:
        warnings.append(f"{decode_errors:,} packets/payloads could not be decoded")
    if non_ip:
        warnings.append(f"{non_ip:,} non-IP or unsupported link-layer packets skipped")

    text = CappedText()
    text.add(f"Packet capture ({kind}), link type {linktype}: {packets:,} packets, "
             f"{len(flows):,} flows, {iso_utc(first_ts) or '?'} to {iso_utc(last_ts) or '?'}")
    text.add("Protocols: " + ", ".join(f"{k}={v:,}" for k, v in protocols.most_common()))
    text.add("Top talkers (bytes sent): " + ", ".join(
        f"{host}={count:,}" for host, count in talkers.most_common(10)))
    for title, lines in (("DNS", dns_lines), ("HTTP requests", http_lines),
                         ("TLS server names", tls_lines)):
        if lines:
            text.add(f"\n== {title} ({len(lines):,}) ==")
            for line in lines:
                if not text.add(line):
                    break
    text.add(f"\n== Flows ({len(flows):,}, by bytes) ==")
    for (proto, src, sport, dst, dport), flow in sorted(
            flows.items(), key=lambda item: -item[1]["bytes"]):
        line = (f"{proto} {src}:{sport} <-> {dst}:{dport} packets={flow['packets']:,} "
                f"bytes={flow['bytes']:,} first={iso_utc(flow['first'])} last={iso_utc(flow['last'])}")
        if not text.add(line):
            break

    metadata = {
        "format": kind,
        "link_type": linktype,
        "packet_count": packets,
        "flow_count": len(flows),
        "first_packet": iso_utc(first_ts),
        "last_packet": iso_utc(last_ts),
        "protocols": dict(protocols.most_common()),
        "top_talkers": dict(talkers.most_common(10)),
        "dns_events": len(dns_lines),
        "http_requests": len(http_lines),
        "tls_sni": len(tls_lines),
    }
    status = f"PCAP parsed: {packets:,} packets, {len(flows):,} flows"
    return _result(text, timeline, metadata, status, warnings)


# --------------------------------------------------------------------------
# Disk images
# --------------------------------------------------------------------------

def _open_image(path: Path, warnings: list[str], suffix: str | None = None):
    import pytsk3

    suffix = (suffix or path.suffix).lower()
    if suffix in (".e01", ".ex01"):
        import pyewf

        try:
            segments = pyewf.glob(str(path))
        except Exception:
            segments = [str(path)]
        handle = pyewf.handle()
        try:
            handle.open(segments)
        except Exception as exc:
            raise ValueError(f"Unable to open EWF image: {exc}") from exc

        class EWFImgInfo(pytsk3.Img_Info):
            def __init__(self, ewf_handle):
                self._ewf = ewf_handle
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def close(self):
                self._ewf.close()

            def read(self, offset, size):
                self._ewf.seek(offset)
                return self._ewf.read(size)

            def get_size(self):
                return self._ewf.get_media_size()

        info = {"container": "ewf", "segments": [Path(s).name for s in segments]}
        try:
            stored = handle.get_hash_value("MD5")
            if stored:
                info["stored_md5"] = stored
        except Exception:
            pass
        return EWFImgInfo(handle), info
    try:
        return pytsk3.Img_Info(str(path)), {"container": "raw"}
    except Exception as exc:
        raise ValueError(f"Unable to open disk image: {exc}") from exc


def _filesystems(image, warnings: list[str]):
    import pytsk3

    found = []
    partitions = []
    try:
        volume = pytsk3.Volume_Info(image)
        block = volume.info.block_size
        for part in volume:
            desc = part.desc.decode("utf-8", "replace") if isinstance(part.desc, bytes) else str(part.desc)
            partitions.append({"start_sector": part.start, "sectors": part.len, "description": desc})
            if not part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                continue
            try:
                fs = pytsk3.FS_Info(image, offset=part.start * block)
                found.append((part.start * block, desc, fs))
            except Exception:
                warnings.append(f"No readable filesystem in partition '{desc}' at sector {part.start}")
    except Exception:
        pass
    if not found:
        try:
            found.append((0, "whole image", pytsk3.FS_Info(image, offset=0)))
        except Exception:
            pass
    return found, partitions


def _fs_type_name(fs) -> str:
    try:
        return str(fs.info.ftype).replace("TSK_FS_TYPE_", "")
    except Exception:
        return "unknown"


def parse_disk_image(source: Source, filename: str = "image.dd", progress: Progress = None) -> dict:
    import pytsk3

    suffix = Path(filename).suffix.lower() or ".dd"
    warnings: list[str] = []
    text = CappedText()
    timeline = Timeline()
    with as_path(source, suffix) as path:
        image, container = _open_image(path, warnings, suffix)
        try:
            _notify(progress, 0.05, "Reading partition table")
            filesystems, partitions = _filesystems(image, warnings)
            if not filesystems:
                raise ValueError("No supported filesystem found in disk image")

            entries = 0
            deleted = 0
            text_budget = DISK_TEXT_TOTAL_LIMIT
            extracted_files: list[tuple[str, str]] = []
            fs_summaries = []
            limit_hit = False
            for fs_index, (offset, desc, fs) in enumerate(filesystems):
                fs_name = _fs_type_name(fs)
                fs_summaries.append({"offset": offset, "partition": desc, "type": fs_name})
                prefix = f"/p{fs_index + 1}" if len(filesystems) > 1 else ""
                try:
                    root = fs.open_dir(path="/")
                except Exception as exc:
                    warnings.append(f"Cannot open root directory of {fs_name} at offset {offset}: {exc}")
                    continue
                stack = [(root, "")]
                visited: set[int] = set()
                while stack and not limit_hit:
                    directory, parent = stack.pop()
                    try:
                        listing = list(directory)
                    except Exception as exc:
                        warnings.append(f"Unreadable directory {prefix}{parent or '/'}: {exc}")
                        continue
                    for entry in listing:
                        try:
                            raw_name = entry.info.name.name
                            name = raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)
                            if name in (".", ".."):
                                continue
                            meta = entry.info.meta
                            full = f"{prefix}{parent}/{name}"
                            is_deleted = bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                            is_dir = meta is not None and meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                            size = int(meta.size) if meta is not None else 0
                            inode = int(meta.addr) if meta is not None else int(entry.info.name.meta_addr)
                            times = {}
                            if meta is not None:
                                for label in ("mtime", "atime", "ctime", "crtime"):
                                    times[label] = iso_utc(getattr(meta, label, 0))
                        except Exception:
                            continue
                        entries += 1
                        deleted += is_deleted
                        if entries % 5000 == 0:
                            _notify(progress, 0.5, f"Disk image: {entries:,} entries listed")
                        flag = " [DELETED]" if is_deleted else ""
                        kind = "d" if is_dir else "f"
                        text.add(
                            f"{kind} {full}{flag} size={size:,} inode={inode} "
                            f"mtime={times.get('mtime') or '-'} atime={times.get('atime') or '-'} "
                            f"ctime={times.get('ctime') or '-'} crtime={times.get('crtime') or '-'}"
                        )
                        fields = {"path": full, "size": size, "inode": inode,
                                  "deleted": is_deleted, "type": "dir" if is_dir else "file",
                                  "filesystem": fs_name}
                        if times.get("mtime"):
                            timeline.add(times["mtime"], f"Modified {full}{flag}", "filesystem",
                                         {**fields, "time_type": "mtime"})
                        if times.get("crtime"):
                            timeline.add(times["crtime"], f"Created {full}{flag}", "filesystem",
                                         {**fields, "time_type": "crtime"})
                        if (not is_dir and 0 < size < DISK_TEXT_FILE_LIMIT and text_budget > 0
                                and Path(name).suffix.lower() in DISK_TEXT_EXTENSIONS):
                            try:
                                data = entry.read_random(0, min(size, text_budget))
                                content = _decode_bytes(data).strip()
                                if content:
                                    extracted_files.append((full + flag, content))
                                    text_budget -= len(content)
                            except Exception:
                                pass
                        if is_dir and inode not in visited and not is_deleted:
                            visited.add(inode)
                            try:
                                stack.append((entry.as_directory(), f"{parent}/{name}"))
                            except Exception:
                                pass
                        if entries >= MAX_DISK_ENTRIES:
                            limit_hit = True
                            warnings.append(f"File listing capped at {MAX_DISK_ENTRIES:,} entries")
                            break
            if extracted_files:
                text.add(f"\n== Text content of {len(extracted_files)} small files ==")
                for name, content in extracted_files:
                    if not text.add(f"--- {name} ---\n{content}"):
                        break
            if text_budget <= 0:
                warnings.append(f"Embedded file text capped at {DISK_TEXT_TOTAL_LIMIT:,} characters")
        finally:
            try:
                image.close()
            except Exception:
                pass

    metadata = {
        "format": "disk_image",
        **container,
        "partitions": partitions,
        "filesystems": fs_summaries,
        "file_entries": entries,
        "deleted_entries": deleted,
        "text_files_extracted": len(extracted_files),
    }
    status = (f"Disk image parsed: {entries:,} entries in {len(fs_summaries)} filesystem(s)"
              + (f", {deleted:,} deleted" if deleted else ""))
    return _result(text, timeline, metadata, status, warnings)


def _decode_bytes(data: bytes) -> str:
    for bom, codec in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(codec, errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


# --------------------------------------------------------------------------
# Memory dumps
# --------------------------------------------------------------------------

_IPV4_RE = re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_URL_RE = re.compile(rb"\b(?:https?|ftp)://[A-Za-z0-9.\-]+(?::\d+)?(?:/[\x21-\x7e]*)?")
_EMAIL_RE = re.compile(rb"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b")
_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

VOL_PLUGINS_WINDOWS = ("windows.info", "windows.pslist", "windows.netscan")
VOL_PLUGINS_LINUX = ("linux.pslist",)


def volatility_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("volatility3") is not None
    except Exception:
        return False


def _run_volatility(path: Path, plugin: str, timeout: float) -> list[dict]:
    command = [sys.executable, "-c",
               "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; sys.exit(main())",
               "-q", "-r", "csv", "-f", str(path)]
    if os.environ.get("TRACE_VOL_OFFLINE", "").strip() in ("1", "true", "yes"):
        command.append("--offline")
    command.append(plugin)
    completed = subprocess.run(command, capture_output=True, text=True,
                               timeout=max(1.0, timeout), errors="replace")
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output:
        error = (completed.stderr or "").strip().splitlines()
        raise RuntimeError(error[-1] if error else f"exit code {completed.returncode}")
    lines = output.splitlines()
    while lines and "," not in lines[0]:  # drop the "Volatility 3 Framework" banner
        lines.pop(0)
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    if not rows:
        raise RuntimeError("plugin produced no rows")
    return rows


def _vol_time(value: str) -> str | None:
    if not value or value in ("N/A", "-"):
        return None
    cleaned = value.strip().replace(" UTC", "+00:00").replace(" ", "T", 1)
    try:
        moment = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return iso_utc(moment)


def _memory_strings(path: Path, text: CappedText, warnings: list[str], progress: Progress) -> dict:
    size = path.stat().st_size
    limit = min(size, MEMORY_SAMPLE_BYTES)
    if size > MEMORY_SAMPLE_BYTES:
        warnings.append(f"Strings scanned from the first {MEMORY_SAMPLE_BYTES // (1024 * 1024)} MB "
                        f"of {size:,} bytes only")
    ips: Counter = Counter()
    urls: Counter = Counter()
    emails: Counter = Counter()
    strings: list[str] = []
    string_chars = 0
    string_budget = 2_000_000
    read = 0
    tail = b""
    with open(path, "rb") as handle:
        while read < limit:
            chunk = handle.read(min(BLOCK_SIZE, limit - read))
            if not chunk:
                break
            read += len(chunk)
            data = tail + chunk
            tail = b""
            final = read >= limit
            found = []
            carry_from = len(data)
            for pattern, utf16 in ((_ASCII_RE, False), (_UTF16_RE, True)):
                for match in pattern.finditer(data):
                    # A run touching the buffer end may continue in the next block.
                    if not final and match.end() >= len(data) - 1:
                        carry_from = min(carry_from, match.start())
                        continue
                    value = match.group()
                    if utf16:
                        value = value.decode("utf-16-le", "replace").encode("ascii", "replace")
                    found.append(value)
            if carry_from < len(data):
                tail = data[carry_from:][-65536:]
            for value in found:
                for ip in _IPV4_RE.findall(value):
                    if not ip.startswith((b"0.", b"255.")):
                        ips[ip.decode()] += 1
                for url in _URL_RE.findall(value):
                    urls[url.decode()[:500]] += 1
                for email in _EMAIL_RE.findall(value):
                    emails[email.decode().lower()] += 1
                if string_chars < string_budget and len(value) >= 8:
                    decoded = value.decode("ascii", "replace")[:300]
                    strings.append(decoded)
                    string_chars += len(decoded)
            _notify(progress, 0.1 + 0.8 * read / max(1, limit),
                    f"Memory strings: {read // (1024 * 1024)} MB scanned")
    text.add(f"== Indicators: {len(ips):,} IPv4, {len(urls):,} URLs, {len(emails):,} emails ==")
    for label, counter in (("IP", ips), ("URL", urls), ("EMAIL", emails)):
        for value, count in counter.most_common(5000):
            text.add(f"{label} {value} (x{count})")
    if string_chars >= string_budget:
        warnings.append(f"Raw strings listing capped at {string_budget:,} characters")
    text.add(f"\n== Printable strings (min length 8, first {len(strings):,}) ==")
    for value in strings:
        if not text.add(value):
            break
    return {
        "bytes_scanned": read,
        "ipv4_count": len(ips),
        "url_count": len(urls),
        "email_count": len(emails),
        "top_ips": dict(ips.most_common(20)),
        "top_urls": dict(urls.most_common(20)),
        "top_emails": dict(emails.most_common(20)),
    }


def analyze_memory(source: Source, filename: str = "memory.mem", progress: Progress = None) -> dict:
    warnings: list[str] = []
    text = CappedText()
    timeline = Timeline()
    metadata: dict = {"format": "memory_dump"}
    suffix = Path(filename).suffix.lower() or ".mem"
    with as_path(source, suffix) as path:
        metadata["size_bytes"] = path.stat().st_size
        if metadata["size_bytes"] == 0:
            raise ValueError("Memory dump is empty")
        plugin_results: dict[str, int] = {}
        vol_note = ""
        if volatility_available():
            budget = float(os.environ.get("TRACE_VOL_TIMEOUT", "900") or 900)
            started = datetime.now()
            errors = []
            for plugins in (VOL_PLUGINS_WINDOWS, VOL_PLUGINS_LINUX):
                for plugin in plugins:
                    remaining = budget - (datetime.now() - started).total_seconds()
                    if remaining <= 1:
                        errors.append(f"{plugin}: time budget exhausted")
                        break
                    _notify(progress, 0.1, f"volatility3: running {plugin}")
                    try:
                        rows = _run_volatility(path, plugin, remaining)
                    except subprocess.TimeoutExpired:
                        errors.append(f"{plugin}: timed out")
                        break
                    except Exception as exc:
                        errors.append(f"{plugin}: {exc}")
                        if plugin.endswith(".info"):
                            break  # profile not Windows; skip remaining Windows plugins
                        continue
                    plugin_results[plugin] = len(rows)
                    text.add(f"== volatility3 {plugin} ({len(rows):,} rows) ==")
                    columns = list(rows[0].keys())
                    text.add(" | ".join(columns))
                    for row in rows:
                        text.add(" | ".join(str(row.get(c, "")) for c in columns))
                        if plugin.endswith("pslist"):
                            stamp = _vol_time(row.get("CreateTime", "") or row.get("Start Time", ""))
                            name = row.get("ImageFileName") or row.get("COMM") or row.get("Name") or "?"
                            timeline.add(stamp, f"Process start {name} PID {row.get('PID', '?')}",
                                         "memory", {"plugin": plugin, "process": name,
                                                    "pid": row.get("PID"), "ppid": row.get("PPID")})
                        elif plugin.endswith("netscan"):
                            stamp = _vol_time(row.get("Created", ""))
                            timeline.add(stamp, (f"Connection {row.get('Proto', '')} "
                                                 f"{row.get('LocalAddr', '')}:{row.get('LocalPort', '')} -> "
                                                 f"{row.get('ForeignAddr', '')}:{row.get('ForeignPort', '')} "
                                                 f"{row.get('State', '')} {row.get('Owner', '')}"),
                                         "memory", {"plugin": plugin, "owner": row.get("Owner"),
                                                    "foreign": row.get("ForeignAddr"),
                                                    "pid": row.get("PID")})
                if plugin_results:
                    break
            if errors:
                warnings.extend(f"volatility3 {e}" for e in errors)
            if not plugin_results:
                vol_note = "volatility3 could not analyse this image — strings only"
        else:
            vol_note = "volatility3 not installed — strings only"
        metadata["volatility_plugins"] = plugin_results
        if not plugin_results:
            metadata["strings"] = _memory_strings(path, text, warnings, progress)
            status = f"Memory dump: {vol_note}"
        else:
            status = f"Memory analysed with volatility3 ({', '.join(plugin_results)})"
    return _result(text, timeline, metadata, status, warnings)


def looks_like_filesystem_image(path: Path) -> bool:
    """True when pytsk3 can find a partition table or filesystem in a raw image."""
    try:
        image, _ = _open_image(path, [])
    except Exception:
        return False
    try:
        found, _ = _filesystems(image, [])
        return bool(found)
    finally:
        try:
            image.close()
        except Exception:
            pass


def tool_status() -> dict:
    status = {}
    for name, module in (("evtx", "Evtx"), ("pcap", "dpkt"), ("disk", "pytsk3"),
                         ("ewf", "pyewf"), ("volatility3", "volatility3")):
        try:
            import importlib.util
            status[name] = importlib.util.find_spec(module) is not None
        except Exception:
            status[name] = False
    return status
