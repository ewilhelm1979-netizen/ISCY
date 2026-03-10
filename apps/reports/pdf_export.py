"""V20: Professioneller PDF-Report-Export (Audit-ready)."""
import io
from datetime import date

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from apps.organizations.sector_catalog import get_sector_definition
from apps.risks.services import RiskMatrixService


# ── Farben ──
BLUE = colors.HexColor('#1e40af')
BLUE_LIGHT = colors.HexColor('#dbeafe')
RED = colors.HexColor('#dc2626')
ORANGE = colors.HexColor('#ea580c')
AMBER = colors.HexColor('#f59e0b')
GREEN = colors.HexColor('#22c55e')
GRAY = colors.HexColor('#64748b')
GRAY_LIGHT = colors.HexColor('#f1f5f9')
BLACK = colors.HexColor('#0f172a')
WHITE = colors.white


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle('DocTitle', parent=ss['Heading1'], fontSize=20, textColor=BLUE, spaceAfter=6))
    ss.add(ParagraphStyle('DocSubtitle', parent=ss['Normal'], fontSize=10, textColor=GRAY, spaceAfter=14))
    ss.add(ParagraphStyle('SectionHead', parent=ss['Heading2'], fontSize=13, textColor=BLUE, spaceBefore=16, spaceAfter=6))
    ss.add(ParagraphStyle('BodyText2', parent=ss['Normal'], fontSize=9, leading=13, textColor=BLACK))
    ss.add(ParagraphStyle('SmallGray', parent=ss['Normal'], fontSize=8, textColor=GRAY))
    ss.add(ParagraphStyle('CellText', parent=ss['Normal'], fontSize=8, leading=10, textColor=BLACK))
    ss.add(ParagraphStyle('CellBold', parent=ss['Normal'], fontSize=8, leading=10, textColor=BLACK, fontName='Helvetica-Bold'))
    return ss


def _header_footer(canvas_obj, doc, tenant_name, report_title):
    canvas_obj.saveState()
    canvas_obj.setFont('Helvetica', 7)
    canvas_obj.setFillColor(GRAY)
    canvas_obj.drawString(2 * cm, A4[1] - 1.2 * cm, f'{tenant_name} – {report_title}')
    canvas_obj.drawRightString(A4[0] - 2 * cm, A4[1] - 1.2 * cm, f'Erstellt: {date.today().strftime("%d.%m.%Y")}')
    canvas_obj.drawString(2 * cm, 1.2 * cm, 'Vertraulich – Nur fuer internen Gebrauch')
    canvas_obj.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f'Seite {doc.page}')
    canvas_obj.setStrokeColor(colors.HexColor('#dbe4f0'))
    canvas_obj.line(2 * cm, A4[1] - 1.4 * cm, A4[0] - 2 * cm, A4[1] - 1.4 * cm)
    canvas_obj.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas_obj.restoreState()


def _kpi_table(data, col_widths=None):
    """Baut eine formatierte KPI-Tabelle."""
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dbe4f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, GRAY_LIGHT]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def generate_audit_report_pdf(report, session, tenant):
    """Generiert einen professionellen PDF-Report."""
    buffer = io.BytesIO()
    ss = _styles()
    sector = get_sector_definition(tenant.sector)
    report_title = f'ISMS Assessment Report – {tenant.name}'

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
        title=report_title,
    )
    story = []

    # ── Titelseite ──
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph(report_title, ss['DocTitle']))
    story.append(Paragraph(f'{tenant.name} · Sektor: {sector.label} · {date.today().strftime("%d.%m.%Y")}', ss['DocSubtitle']))
    story.append(HRFlowable(width='100%', thickness=1, color=BLUE, spaceAfter=12))
    if report.executive_summary:
        story.append(Paragraph(report.executive_summary, ss['BodyText2']))
    story.append(Spacer(1, 1 * cm))

    # KPI-Box
    kpi_data = [
        ['Kennzahl', 'Wert'],
        ['ISO-27001-Readiness', f'{report.iso_readiness_percent}%'],
        ['NIS2-Readiness', f'{report.nis2_readiness_percent}%' if report.nis2_readiness_percent else 'n/a'],
        ['Betroffenheitsindikation', report.applicability_result or '–'],
        ['Sektor', sector.label],
        ['Sektorbezug', sector.indicative_classification],
    ]
    story.append(_kpi_table(kpi_data, col_widths=[200, 280]))
    story.append(PageBreak())

    # ── Domain Scores ──
    story.append(Paragraph('Reifegrad nach Domaene', ss['SectionHead']))
    if report.domain_scores_json:
        ds_data = [['Domaene', 'Readiness %', 'Reifegrad']]
        for ds in report.domain_scores_json:
            ds_data.append([ds.get('domain', ''), f'{ds.get("score_percent", 0)}%', ds.get('maturity_level', '')])
        story.append(_kpi_table(ds_data, col_widths=[200, 80, 200]))
    else:
        story.append(Paragraph('Keine Domaen-Scores verfuegbar.', ss['SmallGray']))
    story.append(Spacer(1, 8 * mm))

    # ── Top Gaps ──
    story.append(Paragraph('Wichtigste Gaps', ss['SectionHead']))
    if report.top_gaps_json:
        gap_data = [['Gap', 'Schwere']]
        for gap in report.top_gaps_json[:10]:
            gap_data.append([
                Paragraph(gap.get('title', ''), ss['CellText']),
                gap.get('severity', ''),
            ])
        story.append(_kpi_table(gap_data, col_widths=[360, 120]))
    else:
        story.append(Paragraph('Keine Gaps identifiziert.', ss['SmallGray']))
    story.append(Spacer(1, 8 * mm))

    # ── Top Massnahmen ──
    story.append(Paragraph('Priorisierte Massnahmen', ss['SectionHead']))
    if report.top_measures_json:
        m_data = [['Massnahme', 'Prioritaet', 'Phase']]
        for m in report.top_measures_json[:10]:
            m_data.append([
                Paragraph(m.get('title', ''), ss['CellText']),
                m.get('priority', ''),
                m.get('target_phase', ''),
            ])
        story.append(_kpi_table(m_data, col_widths=[240, 80, 160]))
    story.append(PageBreak())

    # ── Roadmap ──
    story.append(Paragraph('Umsetzungsroadmap', ss['SectionHead']))
    if report.roadmap_summary:
        r_data = [['Phase', 'Wochen', 'Ziel']]
        for phase in report.roadmap_summary:
            r_data.append([
                phase.get('name', ''),
                str(phase.get('duration_weeks', '')),
                Paragraph(phase.get('objective', ''), ss['CellText']),
            ])
        story.append(_kpi_table(r_data, col_widths=[140, 50, 290]))
    story.append(Spacer(1, 8 * mm))

    # ── Naechste Schritte ──
    story.append(Paragraph('Empfohlene naechste Schritte', ss['SectionHead']))
    if report.next_steps_json:
        for period, label in [('next_30_days', '30 Tage'), ('next_60_days', '60 Tage'), ('next_90_days', '90 Tage')]:
            items = report.next_steps_json.get(period, [])
            if items:
                story.append(Paragraph(f'<b>Innerhalb von {label}:</b>', ss['BodyText2']))
                for item in items:
                    story.append(Paragraph(f'  • {item.get("title", "")} ({item.get("priority", "")})', ss['BodyText2']))
                story.append(Spacer(1, 4 * mm))

    # ── Risk Heatmap (text) ──
    story.append(Paragraph('Risikomatrix-Zusammenfassung', ss['SectionHead']))
    from apps.risks.models import Risk
    risks = Risk.objects.filter(tenant=tenant)
    if risks.exists():
        summary = RiskMatrixService.summary(risks)
        risk_data = [
            ['Level', 'Anzahl'],
            ['Kritisch', str(summary['critical'])],
            ['Hoch', str(summary['high'])],
            ['Mittel', str(summary['medium'])],
            ['Niedrig', str(summary['low'])],
            ['Gesamt', str(summary['total'])],
        ]
        story.append(_kpi_table(risk_data, col_widths=[200, 80]))
    else:
        story.append(Paragraph('Keine Risiken im Register erfasst.', ss['SmallGray']))

    # ── Disclaimer ──
    story.append(Spacer(1, 2 * cm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#dbe4f0'), spaceAfter=8))
    story.append(Paragraph(
        'Dieses Dokument ist das Ergebnis einer strukturierten Bewertung und ersetzt keine rechtliche Pruefung. '
        'Die dargestellten Ergebnisse sind als Indikation und Dokumentationsgrundlage zu verstehen.',
        ss['SmallGray'],
    ))

    def on_page(canvas_obj, doc_obj):
        _header_footer(canvas_obj, doc_obj, tenant.name, 'ISMS Assessment Report')

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()
