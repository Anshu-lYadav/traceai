import glob
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image, ImageDraw, ImageFont

from modules import evidence_processor as ep
from modules import forensics
from modules.ocr import ocr_image_bytes, ocr_status


class MemoryUpload:
    def __init__(self, name, content):
        self.name = name
        self._content = content

    def getvalue(self):
        return self._content


def _font(size=48):
    for pattern in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                    "/usr/share/fonts/**/*Sans*.ttf", "/usr/share/fonts/**/*.ttf"):
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return ImageFont.truetype(matches[0], size)
    return ImageFont.load_default(size=size)


def text_png(text="TRACE EVIDENCE 4521", size=(900, 140)):
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).text((30, 35), text, font=_font(), fill="black")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _rapidocr_ready():
    return ocr_status()["any_available"]


class TextDecodingTests(unittest.TestCase):
    def test_utf16_text(self):
        content = "Suspect: José Müller — हिन्दी नोट".encode("utf-16")
        item = ep.process_upload(MemoryUpload("note.txt", content), "CASE-X")
        self.assertIn("José Müller", item["text"])
        self.assertIn("हिन्दी", item["text"])
        self.assertTrue(item["metadata"]["encoding"].startswith("utf-16"))

    def test_cp1252_text(self):
        content = ("Payment of €500 sent to François; “urgent” transfer — "
                   "déjà vu at the café near the façade.\n").encode("cp1252") * 3
        item = ep.process_upload(MemoryUpload("payment.log", content), "CASE-X")
        self.assertIn("€500", item["text"])
        self.assertIn("François", item["text"])
        self.assertNotIn("�", item["text"])
        self.assertIn("encoding", item["metadata"])

    def test_csv_timeline(self):
        content = (b"timestamp,user,action\n"
                   b"2024-03-01T10:00:00Z,alice,login\n"
                   b"2024-03-01 12:30:00,bob,download\n"
                   b"not a date,carol,noop\n")
        item = ep.process_upload(MemoryUpload("events.csv", content), "CASE-X")
        timeline = item["timeline"]
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0]["timestamp"], "2024-03-01T10:00:00Z")
        self.assertEqual(timeline[0]["source"], "csv")
        self.assertEqual(timeline[0]["fields"]["user"], "alice")
        self.assertEqual(timeline[1]["fields"]["timezone"], "unspecified")

    def test_json_timeline_and_text(self):
        records = {"events": [{"created_at": 1700000000, "host": "srv1"},
                              {"created_at": "2024-01-02T03:04:05+05:30", "host": "srv2"}]}
        item = ep.process_upload(MemoryUpload("e.json", json.dumps(records).encode()), "CASE-X")
        stamps = [entry["timestamp"] for entry in item["timeline"]]
        self.assertEqual(stamps, ["2023-11-14T22:13:20Z", "2024-01-01T21:34:05Z"])
        self.assertIn('"host": "srv1"', item["text"])

    def test_text_cap(self):
        with patch.object(ep, "MAX_TEXT_CHARS", 1000):
            item = ep.process_upload(MemoryUpload("big.txt", b"a" * 5000), "CASE-X")
        self.assertIn("[truncated", item["text"])
        self.assertTrue(item["metadata"]["text_truncated"])

    def test_process_path_streams_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "notes.txt"
            path.write_bytes(b"hello path evidence")
            calls = []
            item = ep.process_path(path, "CASE-P", progress=lambda f, m: calls.append(f))
            upload_item = ep.process_upload(MemoryUpload("notes.txt", b"hello path evidence"), "CASE-P")
            self.assertEqual(item["sha256"], upload_item["sha256"])
            self.assertEqual(item["evidence_id"], upload_item["evidence_id"])
            self.assertEqual(item["text"], "hello path evidence")
            self.assertEqual(calls[-1], 1.0)

    def test_extension_sets(self):
        for ext in (".txt", ".log", ".xml", ".pdf", ".png", ".evtx", ".pcapng", ".e01", ".mem"):
            self.assertIn(ext, ep.SUPPORTED_EXTENSIONS)
        self.assertTrue(ep.LARGE_FILE_EXTENSIONS <= ep.SUPPORTED_EXTENSIONS)
        self.assertIn(".e01", ep.LARGE_FILE_EXTENSIONS)
        self.assertNotIn(".pcap", ep.LARGE_FILE_EXTENSIONS)


@unittest.skipUnless(_rapidocr_ready(), "no OCR engine available")
class OcrTests(unittest.TestCase):
    def test_image_ocr(self):
        item = ep.process_upload(MemoryUpload("shot.png", text_png()), "CASE-O")
        self.assertIn("4521", item["text"])
        self.assertIn("EVIDENCE", item["text"].upper())
        self.assertTrue(item["extraction_status"].startswith("Text extracted (OCR:"))
        self.assertEqual(item["metadata"]["width"], 900)

    def test_blank_image_has_no_text(self):
        buffer = io.BytesIO()
        Image.new("RGB", (200, 100), "white").save(buffer, format="PNG")
        text, engine = ocr_image_bytes(buffer.getvalue())
        self.assertEqual((text, engine), ("", "none"))

    def test_scanned_pdf_ocr(self):
        import fitz

        doc = fitz.open()
        page = doc.new_page(width=612, height=200)
        page.insert_image(fitz.Rect(20, 20, 592, 110), stream=text_png("SCANNED INVOICE 7788"))
        pdf = doc.tobytes()
        doc.close()
        item = ep.process_upload(MemoryUpload("scan.pdf", pdf), "CASE-O")
        self.assertIn("[Page 1 — OCR]", item["text"])
        self.assertIn("7788", item["text"])
        self.assertEqual(item["metadata"]["ocr_pages"], 1)


def build_pcap() -> bytes:
    import dpkt

    def eth(ip):
        return bytes(dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

    def ipv4(src, dst, proto, payload):
        ip = dpkt.ip.IP(src=bytes(map(int, src.split("."))), dst=bytes(map(int, dst.split("."))),
                        p=proto, data=payload)
        ip.len = len(bytes(ip))
        return ip

    query = dpkt.dns.DNS(id=1, qr=dpkt.dns.DNS_Q, rd=1)
    query.qd = [dpkt.dns.DNS.Q(name="evil.example.com", type=dpkt.dns.DNS_A)]
    udp = dpkt.udp.UDP(sport=53000, dport=53, data=bytes(query))
    udp.ulen = len(bytes(udp))

    answer = dpkt.dns.DNS(id=1, qr=dpkt.dns.DNS_R, rd=1, ra=1)
    answer.qd = query.qd
    answer.an = [dpkt.dns.DNS.RR(name="evil.example.com", type=dpkt.dns.DNS_A,
                                 cls=dpkt.dns.DNS_IN, ttl=60, rdata=bytes([203, 0, 113, 9]))]
    udp_answer = dpkt.udp.UDP(sport=53, dport=53000, data=bytes(answer))
    udp_answer.ulen = len(bytes(udp_answer))

    http = (b"GET /payload.bin HTTP/1.1\r\nHost: evil.example.com\r\n"
            b"User-Agent: curl/8.0\r\n\r\n")
    tcp = dpkt.tcp.TCP(sport=40000, dport=80, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                       seq=1, data=http)

    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    writer.writepkt(eth(ipv4("10.0.0.5", "8.8.8.8", dpkt.ip.IP_PROTO_UDP, udp)), ts=1700000000.0)
    writer.writepkt(eth(ipv4("8.8.8.8", "10.0.0.5", dpkt.ip.IP_PROTO_UDP, udp_answer)), ts=1700000000.5)
    writer.writepkt(eth(ipv4("10.0.0.5", "203.0.113.9", dpkt.ip.IP_PROTO_TCP, tcp)), ts=1700000001.0)
    return buffer.getvalue()


class PcapTests(unittest.TestCase):
    def test_dns_and_http(self):
        item = ep.process_upload(MemoryUpload("capture.pcap", build_pcap()), "CASE-N")
        text = item["text"]
        self.assertIn("DNS query evil.example.com", text)
        self.assertIn("A 203.0.113.9", text)
        self.assertIn("HTTP GET http://evil.example.com/payload.bin", text)
        self.assertEqual(item["metadata"]["packet_count"], 3)
        events = {entry["fields"].get("event") for entry in item["timeline"]}
        self.assertTrue({"dns_query", "dns_answer", "http_request", "flow_start"} <= events)
        self.assertTrue(all(entry["timestamp"].endswith("Z") for entry in item["timeline"]))
        self.assertTrue(item["extraction_status"].startswith("PCAP parsed: 3 packets"))

    def test_truncated_pcap_returns_partial(self):
        raw = build_pcap()
        item = ep.process_upload(MemoryUpload("cut.pcap", raw[:-20]), "CASE-N")
        self.assertEqual(item["metadata"]["packet_count"], 2)
        self.assertTrue(any("truncated" in w for w in item["metadata"]["warnings"]))
        self.assertIn("DNS query evil.example.com", item["text"])
        cut_header = ep.process_upload(MemoryUpload("cut2.pcap", raw[:24 + 16 + 10]), "CASE-N")
        self.assertEqual(cut_header["metadata"]["packet_count"], 0)
        self.assertTrue(cut_header["metadata"]["warnings"])

    def test_pcapng(self):
        import dpkt

        reader = dpkt.pcap.Reader(io.BytesIO(build_pcap()))
        buffer = io.BytesIO()
        writer = dpkt.pcapng.Writer(buffer)
        for ts, buf in reader:
            writer.writepkt(buf, ts=ts)
        item = ep.process_upload(MemoryUpload("capture.pcapng", buffer.getvalue()), "CASE-N")
        self.assertEqual(item["metadata"]["format"], "pcapng")
        self.assertIn("DNS query evil.example.com", item["text"])
        self.assertIn("HTTP GET http://evil.example.com/payload.bin", item["text"])

    def test_tls_sni(self):
        sni = b"secret.example.org"
        ext = struct.pack("!HH", 0, len(sni) + 5) + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        body += struct.pack("!H", len(ext)) + ext
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        self.assertEqual(forensics._tls_sni(record), "secret.example.org")

    def test_garbage_pcap_rejected(self):
        with self.assertRaises(ValueError):
            ep.process_upload(MemoryUpload("bad.pcap", b"definitely not a capture"), "CASE-N")


def _add_fat_file(image: Path, slot: int, name83: bytes, cluster: int, content: bytes, deleted=False):
    """Write a file into the FAT12 root directory of a fresh mkfs.fat image."""
    data = bytearray(image.read_bytes())
    bps = struct.unpack_from("<H", data, 11)[0]
    spc = data[13]
    reserved = struct.unpack_from("<H", data, 14)[0]
    fats = data[16]
    root_entries = struct.unpack_from("<H", data, 17)[0]
    spf = struct.unpack_from("<H", data, 22)[0]
    root = (reserved + fats * spf) * bps
    data_start = root + root_entries * 32
    if not deleted:
        for copy in range(fats):  # mark cluster end-of-chain in FAT12
            base = (reserved + copy * spf) * bps
            offset = base + cluster * 3 // 2
            value = struct.unpack_from("<H", data, offset)[0]
            value = (value & 0x000F) | 0xFFF0 if cluster & 1 else (value & 0xF000) | 0x0FFF
            struct.pack_into("<H", data, offset, value)
    fat_date = ((2024 - 1980) << 9) | (3 << 5) | 15
    fat_time = (10 << 11) | (20 << 5)
    entry = bytearray(32)
    entry[0:11] = name83
    if deleted:
        entry[0] = 0xE5
    entry[11] = 0x20
    struct.pack_into("<HH", entry, 14, fat_time, fat_date)  # create time/date
    struct.pack_into("<H", entry, 18, fat_date)
    struct.pack_into("<HHHI", entry, 22, fat_time, fat_date, cluster, len(content))
    data[root + slot * 32: root + slot * 32 + 32] = entry
    start = data_start + (cluster - 2) * spc * bps
    data[start:start + len(content)] = content
    image.write_bytes(bytes(data))


@unittest.skipUnless(shutil.which("mkfs.fat"), "mkfs.fat not installed")
class DiskImageTests(unittest.TestCase):
    def test_fat_raw_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "usb.dd"
            subprocess.run(["mkfs.fat", "-C", "-F", "12", "-n", "TRACE", str(image), "1024"],
                           check=True, capture_output=True)
            _add_fat_file(image, 1, b"NOTES   TXT", 2, b"meet at dock 7 with the drive")
            _add_fat_file(image, 2, b"XLEAKED TXT", 3, b"deleted secret", deleted=True)
            original = image.read_bytes()
            calls = []
            item = ep.process_path(image, "CASE-D", progress=lambda f, m: calls.append(m))
            self.assertEqual(image.read_bytes(), original)  # image never modified
            self.assertIn("NOTES.TXT", item["text"])
            self.assertIn("meet at dock 7", item["text"])
            self.assertIn("[DELETED]", item["text"])
            self.assertGreaterEqual(item["metadata"]["deleted_entries"], 1)
            self.assertTrue(any(e["source"] == "filesystem" and "NOTES.TXT" in e["summary"]
                                for e in item["timeline"]))
            self.assertTrue(item["extraction_status"].startswith("Disk image parsed"))
            self.assertTrue(calls)

            raw_copy = Path(temporary) / "usb.raw"  # ambiguous .raw -> disk when FS found
            raw_copy.write_bytes(original)
            self.assertEqual(ep.process_path(raw_copy, "CASE-D")["metadata"]["format"], "disk_image")

    def test_disk_without_filesystem_rejected(self):
        with self.assertRaises(ValueError):
            ep.process_upload(MemoryUpload("blank.dd", b"\x00" * 65536), "CASE-D")


class MemoryTests(unittest.TestCase):
    blob = (b"\x00" * 1000 + b"connect http://c2.bad.example/beacon?id=7 now\x00"
            + "user mallory@corp.example logged".encode("utf-16-le") + b"\x00\x00"
            + b"peer 198.51.100.23 port 4444\x00" + os.urandom(2000))

    def test_strings_fallback_without_volatility(self):
        with patch.object(forensics, "volatility_available", return_value=False):
            item = ep.process_upload(MemoryUpload("host.mem", self.blob), "CASE-M")
        self.assertIn("volatility3 not installed — strings only", item["extraction_status"])
        self.assertIn("URL http://c2.bad.example/beacon?id=7", item["text"])
        self.assertIn("EMAIL mallory@corp.example", item["text"])
        self.assertIn("IP 198.51.100.23", item["text"])

    def test_volatility_failure_degrades(self):
        def failing(*args, **kwargs):
            raise RuntimeError("Unsatisfied requirement")

        with (patch.object(forensics, "volatility_available", return_value=True),
              patch.object(forensics, "_run_volatility", side_effect=failing)):
            item = ep.process_upload(MemoryUpload("host.vmem", self.blob), "CASE-M")
        self.assertIn("strings only", item["extraction_status"])
        self.assertIn("IP 198.51.100.23", item["text"])
        self.assertTrue(any("volatility3" in w for w in item["metadata"]["warnings"]))

    def test_raw_without_filesystem_is_memory(self):
        with patch.object(forensics, "volatility_available", return_value=False):
            item = ep.process_upload(MemoryUpload("dump.raw", self.blob), "CASE-M")
        self.assertEqual(item["metadata"]["format"], "memory_dump")


class EvtxTests(unittest.TestCase):
    def test_invalid_evtx_rejected(self):
        with self.assertRaises(ValueError):
            ep.process_upload(MemoryUpload("Security.evtx", b"not an event log"), "CASE-E")

    def test_sample_evtx_if_present(self):
        samples = [p for p in glob.glob("/usr/share/**/*.evtx", recursive=True)][:1]
        samples += glob.glob(os.environ.get("TRACE_SAMPLE_EVTX", "") or "/nonexistent")
        if not samples:
            self.skipTest("no sample .evtx available (python-evtx cannot write fixtures)")
        item = ep.process_path(Path(samples[0]), "CASE-E")
        self.assertTrue(item["extraction_status"].startswith("EVTX parsed"))

    def test_record_xml_parsing(self):
        xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
            '<TimeCreated SystemTime="2024-01-01 08:00:00.1234567+00:00"/>'
            '<Channel>Security</Channel><Computer>WS01</Computer></System>'
            '<EventData><Data Name="TargetUserName">alice</Data>'
            '<Data Name="IpAddress">10.1.1.1</Data></EventData></Event>'
        )
        fields = forensics._evtx_record_fields(xml)
        self.assertEqual(fields["EventID"], "4624")
        self.assertEqual(fields["TimeCreated"], "2024-01-01T08:00:00Z")
        self.assertEqual(fields["data"]["IpAddress"], "10.1.1.1")
        self.assertEqual(fields["Provider"], "Microsoft-Windows-Security-Auditing")


if __name__ == "__main__":
    unittest.main()
