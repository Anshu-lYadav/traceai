import re
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path

def make_report(case_id, evidence):
    lines = [
        "TRACE AI — DRAFT EVIDENCE INVENTORY",
        f"Case ID: {case_id}",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "This is an automatically generated inventory, not a forensic certification or legal conclusion.",
        f"Evidence count: {len(evidence)}",
        ""
    ]
    for item in evidence:
        lines.extend([
            f'{item["evidence_id"]} | {item["filename"]}',
            f'Type: {item["file_type"]}',
            f'SHA-256: {item["sha256"]}',
            f'Extracted characters: {len(item["text"])}',
            ""
        ])
    return "\n".join(lines)


def make_case_diary(case_id, case_name, activity):
    lines = [
        "TRACE AI - DRAFT CASE DIARY",
        f"Case ID: {case_id}",
        f"Case name: {case_name}",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "Application-recorded activity (chronological)",
        "",
    ]
    for entry in activity:
        details = entry.get("details", {})
        summary = "; ".join(f"{key}: {value}" for key, value in details.items())
        lines.append(f"{entry['created_at']} | {entry['event_type']} | {summary}")
    lines.extend([
        "",
        "This draft includes only events recorded by TRACE AI and investigator-entered notes. "
        "It is not a complete audit record or a certified chain-of-custody document.",
    ])
    return "\n".join(lines)


_DEVANAGARI_FONT_DIRS = (
    Path("/usr/share/fonts/truetype/noto"),
    Path("/usr/share/fonts/opentype/noto"),
    Path("C:/Windows/Fonts"),
)
_DEVANAGARI_FONTS = ("NotoSansDevanagari-Regular.ttf", "Nirmala.ttf", "mangal.ttf")


def _devanagari_font():
    for directory in _DEVANAGARI_FONT_DIRS:
        for name in _DEVANAGARI_FONTS:
            if (directory / name).is_file():
                return directory, name
    return None


def _make_shaped_pdf(title, text, font):
    """Render with PyMuPDF's HTML engine, which shapes Devanagari conjuncts correctly
    (reportlab draws Indic text without shaping, so matras and conjuncts break)."""
    import pymupdf

    directory, font_name = font
    css = (
        f"@font-face {{font-family: deva; src: url({font_name});}}"
        "body {font-family: deva, sans-serif; font-size: 10.5pt; line-height: 1.45;}"
        "h1 {font-size: 16pt; margin-bottom: 10pt;} p {margin: 0 0 4pt 0; white-space: pre-wrap;}"
    )
    body = "".join(f"<p>{escape(line) or '&nbsp;'}</p>" for line in text.splitlines())
    html = f"<h1>{escape(title)}</h1>{body}"
    story = pymupdf.Story(html=html, user_css=css, archive=pymupdf.Archive(str(directory)))
    buffer = BytesIO()
    writer = pymupdf.DocumentWriter(buffer)
    mediabox = pymupdf.paper_rect("letter")
    where = mediabox + (47, 47, -47, -47)
    more = True
    while more:
        device = writer.begin_page(mediabox)
        more, _ = story.place(where)
        story.draw(device)
        writer.end_page()
    writer.close()
    return buffer.getvalue()


def make_pdf(title, text, language="English"):
    """Create a PDF. Hindi/Devanagari text is shaped properly when a font is available."""
    if re.search(r"[\u0900-\u097F]", f"{title}{text}"):
        font = _devanagari_font()
        if font:
            try:
                return _make_shaped_pdf(title, text, font)
            except Exception:
                pass  # fall back to reportlab below
    from reportlab.lib import pagesizes
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    buffer = BytesIO()
    styles = getSampleStyleSheet()
    font_name = "Helvetica"
    font_candidates = (
        [
            Path("C:/Windows/Fonts/Nirmala.ttf"),
            Path("C:/Windows/Fonts/mangal.ttf"),
            Path("/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf"),
        ] if language == "हिन्दी" else []
    ) + [
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
    ]
    for font_path in font_candidates:
        if font_path.is_file():
            try:
                pdfmetrics.registerFont(TTFont("TraceUnicode", str(font_path)))
                font_name = "TraceUnicode"
                break
            except Exception:
                continue

    body_style = ParagraphStyle(
        "TraceBody", parent=styles["BodyText"], fontName=font_name,
        leading=14, spaceAfter=5,
    )
    title_style = ParagraphStyle(
        "TraceTitle", parent=styles["Title"], fontName=font_name,
    )
    story = [Paragraph(escape(title), title_style), Spacer(1, 0.2 * inch)]
    for line in text.splitlines():
        story.append(Paragraph(escape(line) or "&nbsp;", body_style))

    document = SimpleDocTemplate(
        buffer, pagesize=pagesizes.LETTER,
        rightMargin=0.65 * inch, leftMargin=0.65 * inch,
        topMargin=0.65 * inch, bottomMargin=0.65 * inch,
        title=title,
    )
    document.build(story)
    return buffer.getvalue()


def make_custody_report(case_id, evidence, provenance_by_id, custody_by_id, chain_status=None):
    """Per-item acquisition record and custody history, with audit-chain status."""
    lines = [
        "TRACE AI — CHAIN OF CUSTODY REGISTER",
        f"Case ID: {case_id}",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    if chain_status:
        lines += [
            f"Audit chain: {'VALID' if chain_status.get('valid') else 'PROBLEMS FOUND'} — "
            f"{chain_status.get('entries')} signed entries, head #{chain_status.get('head_seq')} "
            f"{chain_status.get('head_hash')}",
            f"Signing key ID: {chain_status.get('public_key_id')}; trusted timestamp anchors: "
            f"{chain_status.get('anchors')}",
            "",
        ]
    for item in evidence:
        provenance = provenance_by_id.get(item["evidence_id"])
        lines += [
            "=" * 72,
            f'{item["evidence_id"]} | {item["filename"]}',
            f'SHA-256 (vault): {item["sha256"]}',
            f'Size: {item["raw_bytes"]} bytes | Ingested (UTC): {item.get("ingested_at", "")}',
        ]
        if provenance:
            verified = {1: "MATCHES upload", 0: "MISMATCH", None: "not supplied"}[provenance["hash_verified"]]
            lines += [
                f'Source: {provenance["source_description"]}  Device: {provenance["device_identifier"] or "—"}',
                f'Acquired by: {provenance["acquired_by"]} at {provenance["acquired_at"]}',
                f'Method/tool: {provenance["acquisition_method"]} / {provenance["acquisition_tool"] or "—"}',
                f'Legal authority: {provenance["legal_authority"]}',
                f'Certificate (BSA s.63 / IEA s.65B): {provenance["certificate_reference"] or "—"}',
                f'Acquisition hash: {provenance["acquisition_sha256"] or "—"} ({verified})',
                f'Recorded by {provenance["recorded_by"]} at {provenance["recorded_at"]}',
            ]
        else:
            lines.append("Provenance: NOT RECORDED — acquisition origin cannot be shown from this system.")
        lines.append("Custody history:")
        for event in custody_by_id.get(item["evidence_id"], []):
            lines.append(
                f'  {event["occurred_at"]} | {event["action"]} | {event["from_party"] or "—"} → '
                f'{event["to_party"] or "—"} | {event["location"] or "—"} | {event["notes"]} '
                f'(recorded by {event["recorded_by"]})'
            )
        lines.append("")
    lines += [
        "Every entry above is also written to the signed, hash-chained audit log. This register",
        "documents what was recorded in TRACE AI; it does not replace the statutory certificate or",
        "the examiner's testimony about how the evidence was acquired.",
    ]
    return "\n".join(lines)
