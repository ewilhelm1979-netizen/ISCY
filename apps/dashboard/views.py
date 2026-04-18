import io

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.http import HttpResponse
from django.views.generic import TemplateView, View
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from apps.assets_app.models import InformationAsset
from apps.dashboard.services import DashboardSummaryBridge
from apps.evidence.models import EvidenceItem, RequirementEvidenceNeed
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.reports.models import ReportSnapshot
from apps.roadmap.models import RoadmapTask
from apps.risks.models import Risk
from apps.wizard.services import WizardService


class DashboardDataMixin:
    def build_dashboard_context(self, request):
        tenant = WizardService.get_default_tenant(request.user)
        rust_summary = DashboardSummaryBridge.fetch(request, tenant)
        latest_report = ReportSnapshot.objects.filter(tenant=tenant).order_by('-created_at').first() if tenant else None
        roadmap_tasks = RoadmapTask.objects.filter(phase__plan__tenant=tenant) if tenant else RoadmapTask.objects.none()

        selected_sector = request.GET.get('sector', '').strip()
        selected_country = request.GET.get('country', '').strip()
        selected_tenant = request.GET.get('tenant', '').strip()

        all_tenants = Tenant.objects.all()
        comparison_rows = []
        for item in all_tenants:
            if selected_sector and item.sector != selected_sector:
                continue
            countries = item.operation_countries or ([] if not item.country else [item.country])
            country_labels = item.country_labels
            if selected_country and selected_country not in countries and selected_country not in country_labels:
                continue
            report = ReportSnapshot.objects.filter(tenant=item).order_by('-created_at').first()
            comparison_rows.append({
                'tenant': item,
                'sector': item.sector_label,
                'sector_code': item.sector,
                'countries': item.countries_display,
                'iso': report.iso_readiness_percent if report else 0,
                'nis2': report.nis2_readiness_percent if report else 0,
                'open_tasks': RoadmapTask.objects.filter(phase__plan__tenant=item).exclude(status=RoadmapTask.Status.DONE).count(),
                'evidence': EvidenceItem.objects.filter(tenant=item).count(),
                'report_id': report.id if report else None,
            })

        sector_rollup = {}
        country_rollup = {}
        for row in comparison_rows:
            sector_rollup.setdefault(row['sector'], {'count': 0, 'iso_total': 0, 'nis2_total': 0, 'open_tasks': 0, 'evidence': 0})
            sector_rollup[row['sector']]['count'] += 1
            sector_rollup[row['sector']]['iso_total'] += row['iso']
            sector_rollup[row['sector']]['nis2_total'] += row['nis2']
            sector_rollup[row['sector']]['open_tasks'] += row['open_tasks']
            sector_rollup[row['sector']]['evidence'] += row['evidence']
            for label in row['countries'].split(', '):
                if not label or label == '-':
                    continue
                country_rollup.setdefault(label, {'count': 0, 'iso_total': 0, 'nis2_total': 0, 'open_tasks': 0, 'evidence': 0})
                country_rollup[label]['count'] += 1
                country_rollup[label]['iso_total'] += row['iso']
                country_rollup[label]['nis2_total'] += row['nis2']
                country_rollup[label]['open_tasks'] += row['open_tasks']
                country_rollup[label]['evidence'] += row['evidence']
        sector_summary = [
            {'sector': sector, 'tenant_count': values['count'], 'avg_iso': int(values['iso_total'] / values['count']) if values['count'] else 0, 'avg_nis2': int(values['nis2_total'] / values['count']) if values['count'] else 0, 'open_tasks': values['open_tasks'], 'evidence': values['evidence']}
            for sector, values in sector_rollup.items()
        ]
        country_summary = [
            {'country': country, 'tenant_count': values['count'], 'avg_iso': int(values['iso_total'] / values['count']) if values['count'] else 0, 'avg_nis2': int(values['nis2_total'] / values['count']) if values['count'] else 0, 'open_tasks': values['open_tasks'], 'evidence': values['evidence']}
            for country, values in country_rollup.items()
        ]

        drilldown_tenant = Tenant.objects.filter(pk=selected_tenant).first() if selected_tenant else None
        drilldown_report = ReportSnapshot.objects.filter(tenant=drilldown_tenant).order_by('-created_at').first() if drilldown_tenant else None
        drilldown_open_tasks = RoadmapTask.objects.filter(phase__plan__tenant=drilldown_tenant).exclude(status=RoadmapTask.Status.DONE) if drilldown_tenant else []
        drilldown_evidence_needs = RequirementEvidenceNeed.objects.filter(tenant=drilldown_tenant) if drilldown_tenant else []

        sector_heatmap = [
            {'label': item['sector'], 'score': item['avg_nis2'], 'subscore': item['avg_iso'], 'meta': f"{item['tenant_count']} Mandant(en) · {item['open_tasks']} offene Tasks"}
            for item in sector_summary
        ]
        country_heatmap = [
            {'label': item['country'], 'score': item['avg_iso'], 'subscore': item['avg_nis2'], 'meta': f"{item['tenant_count']} Mandant(en) · {item['evidence']} Evidenzen"}
            for item in country_summary
        ]


        top_risks = list(
            Risk.objects.filter(tenant=tenant)
            .exclude(status=Risk.Status.CLOSED)
            .select_related('process')[:6]
        ) if tenant else []
        top_gaps = (latest_report.top_gaps_json[:6] if latest_report and latest_report.top_gaps_json else [])
        top_measures = (latest_report.top_measures_json[:6] if latest_report and latest_report.top_measures_json else [])
        avg_iso = int(sum(r['iso'] for r in comparison_rows) / len(comparison_rows)) if comparison_rows else 0
        avg_nis2 = int(sum(r['nis2'] for r in comparison_rows) / len(comparison_rows)) if comparison_rows else 0
        total_tenants = len(comparison_rows)
        critical_risk_count = sum(1 for risk in top_risks if risk.risk_level == 'CRITICAL')
        high_risk_count = Risk.objects.filter(tenant=tenant).exclude(status=Risk.Status.CLOSED).filter(impact__gte=4, likelihood__gte=3).count() if tenant else 0
        sector_summary = sorted(sector_summary, key=lambda x: (-x['avg_nis2'], x['sector']))
        country_summary = sorted(country_summary, key=lambda x: (-x['avg_iso'], x['country']))

        return {
            'tenant': tenant,
            'process_count': _rust_or_local_count(rust_summary, 'process_count', lambda: Process.objects.filter(tenant=tenant).count() if tenant else 0),
            'asset_count': _rust_or_local_count(rust_summary, 'asset_count', lambda: InformationAsset.objects.filter(tenant=tenant).count() if tenant else 0),
            'open_risk_count': _rust_or_local_count(rust_summary, 'open_risk_count', lambda: Risk.objects.filter(tenant=tenant).exclude(status=Risk.Status.CLOSED).count() if tenant else 0),
            'evidence_count': _rust_or_local_count(rust_summary, 'evidence_count', lambda: EvidenceItem.objects.filter(tenant=tenant).count() if tenant else 0),
            'open_task_count': _rust_or_local_count(rust_summary, 'open_task_count', lambda: roadmap_tasks.exclude(status=RoadmapTask.Status.DONE).count()),
            'dashboard_summary_source': 'rust_service' if rust_summary else 'django',
            'status_distribution': roadmap_tasks.values('status').annotate(total=Count('id')).order_by('status'),
            'latest_report': latest_report,
            'recent_risks': Risk.objects.filter(tenant=tenant).select_related('process')[:10] if tenant else [],
            'sector_context': WizardService.get_sector_context(tenant) if tenant else None,
            'country_context': WizardService.get_country_context(tenant) if tenant else None,
            'total_tenants': total_tenants,
            'portfolio_avg_iso': avg_iso,
            'portfolio_avg_nis2': avg_nis2,
            'top_risks': top_risks,
            'top_gaps': top_gaps,
            'top_measures': top_measures,
            'critical_risk_count': critical_risk_count,
            'high_risk_count': high_risk_count,
            'comparison_rows': comparison_rows,
            'sector_summary': sector_summary,
            'country_summary': country_summary,
            'sector_heatmap': sector_heatmap,
            'country_heatmap': country_heatmap,
            'selected_sector': selected_sector,
            'selected_country': selected_country,
            'selected_tenant': selected_tenant,
            'available_sectors': sorted({(item.sector, item.sector_label) for item in Tenant.objects.all() if item.sector}, key=lambda x: x[1]),
            'available_countries': sorted({label for item in Tenant.objects.all() for label in item.country_labels if label}),
            'all_tenants': all_tenants,
            'drilldown_tenant': drilldown_tenant,
            'drilldown_report': drilldown_report,
            'drilldown_open_tasks': list(drilldown_open_tasks[:8]) if drilldown_tenant else [],
            'drilldown_need_summary': {
                'open': drilldown_evidence_needs.filter(status=RequirementEvidenceNeed.Status.OPEN).count() if drilldown_tenant else 0,
                'partial': drilldown_evidence_needs.filter(status=RequirementEvidenceNeed.Status.PARTIAL).count() if drilldown_tenant else 0,
                'covered': drilldown_evidence_needs.filter(status=RequirementEvidenceNeed.Status.COVERED).count() if drilldown_tenant else 0,
            },
        }


def _rust_or_local_count(rust_summary, key, fallback):
    if rust_summary and key in rust_summary:
        return int(rust_summary.get(key) or 0)
    return fallback()


class DashboardView(LoginRequiredMixin, DashboardDataMixin, TemplateView):
    template_name = 'dashboard/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(self.build_dashboard_context(self.request))
        return context


class DashboardPortfolioPdfView(LoginRequiredMixin, DashboardDataMixin, View):
    def get(self, request, *args, **kwargs):
        context = self.build_dashboard_context(request)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), title='Portfolio Dashboard')
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph('Portfolio-Sicht / Standort- und Sektorvergleich', styles['Title']))
        story.append(Paragraph('Gefilterte Portfolio-Sicht über Mandanten, Sektoren und operative Länder.', styles['BodyText']))
        story.append(Spacer(1, 12))
        if context['comparison_rows']:
            data = [['Mandant', 'Sektor', 'Länder', 'ISO', 'NIS2', 'Offene Tasks', 'Evidenzen']]
            for row in context['comparison_rows']:
                data.append([row['tenant'].name, row['sector'], row['countries'], f"{row['iso']}%", f"{row['nis2']}%", row['open_tasks'], row['evidence']])
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0b3d91')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.4, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor('#eef4fb')]),
            ]))
            story.append(Paragraph('Mandantenvergleich', styles['Heading2']))
            story.append(table)
            story.append(Spacer(1, 12))
        if context['sector_summary']:
            story.append(Paragraph('Sektor-Heatmap', styles['Heading2']))
            sector_data = [['Sektor', 'Ø ISO', 'Ø NIS2', 'Mandanten', 'Offene Tasks']]
            for item in context['sector_summary']:
                sector_data.append([item['sector'], f"{item['avg_iso']}%", f"{item['avg_nis2']}%", item['tenant_count'], item['open_tasks']])
            sector_table = Table(sector_data, repeatRows=1)
            sector_style = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#23395d')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.4, colors.grey),
            ])
            for i, item in enumerate(context['sector_summary'], start=1):
                color = colors.HexColor('#2e7d32') if item['avg_nis2'] >= 80 else colors.HexColor('#1565c0') if item['avg_nis2'] >= 60 else colors.HexColor('#f9a825') if item['avg_nis2'] >= 40 else colors.HexColor('#c62828')
                sector_style.add('BACKGROUND', (2,i), (2,i), color)
                sector_style.add('TEXTCOLOR', (2,i), (2,i), colors.white)
            sector_table.setStyle(sector_style)
            story.append(sector_table)
            story.append(Spacer(1, 12))
        if context['country_summary']:
            story.append(Paragraph('Länder-Heatmap', styles['Heading2']))
            country_data = [['Land', 'Ø ISO', 'Ø NIS2', 'Mandanten', 'Evidenzen']]
            for item in context['country_summary']:
                country_data.append([item['country'], f"{item['avg_iso']}%", f"{item['avg_nis2']}%", item['tenant_count'], item['evidence']])
            country_table = Table(country_data, repeatRows=1)
            country_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#455a64')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.4, colors.grey),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor('#f6f9fc')]),
            ]))
            story.append(country_table)
        doc.build(story)
        pdf = buffer.getvalue()
        buffer.close()
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="portfolio-dashboard.pdf"'
        response.write(pdf)
        return response
