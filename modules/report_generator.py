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


def make_pdf(title, text, language="English"):
    """Create a basic PDF using a locally available Unicode font when possible."""
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
