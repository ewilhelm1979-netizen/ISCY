import io
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, View
from apps.core.mixins import TenantAccessMixin
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from .models import ReportSnapshot
from .services import ReportSnapshotBridge
from apps.evidence.models import RequirementEvidenceNeed
from apps.evidence.services import EvidenceNeedService
from apps.wizard.models import GeneratedMeasure


class ReportListView(TenantAccessMixin, ListView):
    model = ReportSnapshot
    template_name = 'reports/report_list.html'
    context_object_name = 'reports'

    def get_queryset(self):
        rust_reports = ReportSnapshotBridge.fetch_list(self.request, self.get_tenant())
        if rust_reports is not None:
            self.report_snapshot_source = 'rust_service'
            return rust_reports
        self.report_snapshot_source = 'django'
        return super().get_queryset().select_related('tenant')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report_snapshot_source'] = getattr(self, 'report_snapshot_source', 'django')
        return context


class ReportDetailView(TenantAccessMixin, DetailView):
    model = ReportSnapshot
    template_name = 'reports/report_detail.html'
    context_object_name = 'report'

    def get_object(self, queryset=None):
        report_id = self.kwargs.get(self.pk_url_kwarg)
        rust_report = ReportSnapshotBridge.fetch_detail(self.request, self.get_tenant(), report_id)
        if rust_report is not None:
            self.report_snapshot_source = 'rust_service'
            self.check_tenant_access(rust_report)
            return rust_report
        self.report_snapshot_source = 'django'
        return super().get_object(queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        report = self.object
        session_id = getattr(report, 'session_id', None) or getattr(report.session, 'id', None)
        context['evidence_needs'] = RequirementEvidenceNeed.objects.filter(
            tenant=report.tenant,
            session_id=session_id,
        ).select_related('requirement__mapping_version', 'requirement__primary_source')[:20]
        measures = list(
            GeneratedMeasure.objects.filter(session_id=session_id)
            .select_related('domain', 'question')
            .all()[:12]
        )
        context['measure_evidence_rows'] = [
            {'measure': measure, 'summary': EvidenceNeedService.measure_need_summary(measure)}
            for measure in measures
        ]
        context['report_snapshot_source'] = getattr(self, 'report_snapshot_source', 'django')
        return context


class ReportPdfView(TenantAccessMixin, View):
    tenant_filter_field = 'tenant'

    def get(self, request, pk):
        report = get_object_or_404(
            self.filter_queryset_for_tenant(
                ReportSnapshot.objects.select_related('tenant', 'session')
            ),
            pk=pk,
        )
        evidence_needs = RequirementEvidenceNeed.objects.filter(
            tenant=report.tenant,
            session=report.session,
        ).select_related('requirement__mapping_version', 'requirement__primary_source')[:12]
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), title=report.title)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph(report.title, styles['Title']))
        story.append(Paragraph(f'Mandant: {report.tenant.name}', styles['Normal']))
        story.append(Paragraph(f'Betroffenheit: {report.applicability_result}', styles['Normal']))
        story.append(Paragraph(f'Länder / Präsenz: {report.tenant.countries_display}', styles['Normal']))
        story.append(Paragraph(f'Sektor: {report.tenant.sector_label} ({report.tenant.sector_profile.nis2_group})', styles['Normal']))
        if report.compliance_versions_json:
            version_labels = ", ".join(
                f"{key} {value.get('version', '')}"
                for key, value in report.compliance_versions_json.items()
            )
            story.append(Paragraph(f"Mapping-Versionen: {version_labels}", styles['Normal']))
        story.append(Paragraph(report.tenant.sector_profile.downstream_impact, styles['BodyText']))
        story.append(Spacer(1, 12))
        story.append(Paragraph('Executive Summary', styles['Heading2']))
        story.append(Paragraph(report.executive_summary or '-', styles['BodyText']))
        story.append(Spacer(1, 12))
        story.append(Paragraph('Domänenscores / Heatmap', styles['Heading2']))
        table_data = [['Domäne', 'Score', 'Reifegrad', 'Ampel']]
        score_colors = []
        for item in report.domain_scores_json:
            score = int(item.get('score_percent', 0))
            if score <= 20:
                ampel = 'Rot'; c = colors.HexColor('#c62828')
            elif score <= 40:
                ampel = 'Orange'; c = colors.HexColor('#ef6c00')
            elif score <= 60:
                ampel = 'Gelb'; c = colors.HexColor('#f9a825')
            elif score <= 80:
                ampel = 'Blau'; c = colors.HexColor('#1565c0')
            else:
                ampel = 'Grün'; c = colors.HexColor('#2e7d32')
            table_data.append([item.get('domain', ''), f"{score}%", item.get('maturity_level', ''), ampel])
            score_colors.append(c)
        table = Table(table_data, repeatRows=1)
        style = TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0b3d91')), ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor('#eef4fb')])])
        for idx, color in enumerate(score_colors, start=1):
            style.add('BACKGROUND', (3, idx), (3, idx), color)
            style.add('TEXTCOLOR', (3, idx), (3, idx), colors.white)
        table.setStyle(style)
        story.append(table)
        story.append(Spacer(1, 12))
        story.append(Paragraph('Top Maßnahmen', styles['Heading2']))
        for item in report.top_measures_json:
            story.append(Paragraph(f"• {item.get('title')} ({item.get('priority', '-')})", styles['BodyText']))
        if evidence_needs:
            story.append(Spacer(1, 12))
            story.append(Paragraph('Evidenzpflichten je Requirement', styles['Heading2']))
            for need in evidence_needs:
                story.append(Paragraph(f"• {need.requirement.framework} {need.requirement.code}: {need.get_status_display()} – {need.description}", styles['BodyText']))
                if need.requirement_mapping_version:
                    story.append(Paragraph(f"  Mapping-Version: {need.requirement_mapping_version}", styles['BodyText']))
                if need.requirement_source_citation:
                    story.append(Paragraph(f"  Quelle: {need.requirement_source_citation}", styles['BodyText']))
        story.append(Spacer(1, 12))
        story.append(Paragraph('Maßnahmen mit Nachweispflichten', styles['Heading2']))
        for measure in report.session.generated_measures.select_related('domain')[:8]:
            summary = EvidenceNeedService.measure_need_summary(measure)
            story.append(Paragraph(f"• {measure.title}: offen {summary['open']}, teilweise {summary['partial']}, abgedeckt {summary['covered']}", styles['BodyText']))
        deps = report.next_steps_json.get('dependencies', [])
        if deps:
            story.append(Spacer(1, 12))
            story.append(Paragraph('Wesentliche Abhängigkeiten', styles['Heading2']))
            for dep in deps[:10]:
                story.append(Paragraph(f"• {dep.get('predecessor')} → {dep.get('successor')} ({dep.get('type')})", styles['BodyText']))
        story.append(Spacer(1, 12))
        story.append(Paragraph('Roadmap', styles['Heading2']))
        for item in report.roadmap_summary:
            story.append(Paragraph(f"• {item.get('name')} – {item.get('duration_weeks', '-') } Wochen", styles['BodyText']))
            if item.get('objective'):
                story.append(Paragraph(item['objective'], styles['Normal']))
        doc.build(story)
        pdf = buffer.getvalue()
        buffer.close()
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report-{report.pk}.pdf"'
        response.write(pdf)
        return response


class ReportProPdfView(TenantAccessMixin, View):
    """V20: Professioneller audit-ready PDF-Report."""
    tenant_filter_field = 'tenant'

    def get(self, request, pk):
        report = get_object_or_404(
            self.filter_queryset_for_tenant(
                ReportSnapshot.objects.select_related('tenant', 'session')
            ),
            pk=pk,
        )
        from .pdf_export import generate_audit_report_pdf
        pdf_bytes = generate_audit_report_pdf(report, report.session, report.tenant)
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="ISMS-Report-{report.tenant.name}-{report.pk}.pdf"'
        response.write(pdf_bytes)
        return response
