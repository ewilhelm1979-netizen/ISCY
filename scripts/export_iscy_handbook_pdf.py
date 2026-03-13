#!/usr/bin/env python3
"""Export the repository handbook markdown as a simple PDF."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "ISCY_Handbuch.md"
TARGET = ROOT / "docs" / "ISCY_Handbuch.pdf"


def _styles():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("DocTitle", parent=styles["Heading1"], fontSize=20, leading=24, textColor=colors.HexColor("#0f172a"), spaceAfter=12))
    styles.add(ParagraphStyle("Section", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#1d4ed8"), spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle("SubSection", parent=styles["Heading3"], fontSize=11, leading=14, textColor=colors.HexColor("#334155"), spaceBefore=8, spaceAfter=4))
    styles.add(ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=6))
    styles.add(ParagraphStyle("Bullet2", parent=styles["BodyText"], fontSize=9, leading=12, leftIndent=14, bulletIndent=4, spaceAfter=3))
    return styles


def build_pdf(source: Path = SOURCE, target: Path = TARGET) -> Path:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("reportlab ist nicht installiert. Bitte zuerst die Projekt-Dependencies installieren.") from exc

    if not source.exists():
        raise FileNotFoundError(f"Quelldatei fehlt: {source}")

    styles = _styles()
    story = []
    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            story.append(Spacer(1, 0.15 * cm))
            continue
        if line.startswith("# "):
            story.append(Paragraph(line[2:].strip(), styles["DocTitle"]))
            continue
        if line.startswith("## "):
            story.append(Paragraph(line[3:].strip(), styles["Section"]))
            continue
        if line.startswith("### "):
            story.append(Paragraph(line[4:].strip(), styles["SubSection"]))
            continue
        if line.startswith("- "):
            story.append(Paragraph(line[2:].strip(), styles["Bullet2"], bulletText="•"))
            continue
        if line.startswith(("1. ", "2. ", "3. ", "4. ", "5. ", "6. ", "7. ", "8. ", "9. ")):
            marker, text = line.split(" ", 1)
            story.append(Paragraph(text.strip(), styles["Bullet2"], bulletText=marker))
            continue
        story.append(Paragraph(line, styles["Body"]))

    target.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(target),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="ISCY Handbuch",
    )
    doc.build(story)
    return target


def main() -> int:
    try:
        target = build_pdf()
    except Exception as exc:
        print(f"Fehler beim PDF-Export: {exc}", file=sys.stderr)
        return 1
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
