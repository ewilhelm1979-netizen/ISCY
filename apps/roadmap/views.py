from collections import OrderedDict
from collections import Counter
from datetime import date
import io

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, UpdateView, View
from apps.core.mixins import TenantAccessMixin
from apps.reports.models import ReportSnapshot
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.pdfgen import canvas
from PIL import Image, ImageDraw

from apps.wizard.services import WizardService
from .forms import RoadmapTaskUpdateForm
from .models import RoadmapPlan, RoadmapTask, RoadmapTaskDependency
from .services import RoadmapRegisterBridge


PHASE_COLORS = [
    '#2563eb', '#3b82f6', '#10b981', '#84cc16', '#f59e0b', '#8b5cf6', '#ec4899'
]
THEMES = {
    'ocean': {'shell': 'roadmap-theme-ocean', 'accent': '#2563eb'},
    'forest': {'shell': 'roadmap-theme-forest', 'accent': '#15803d'},
    'slate': {'shell': 'roadmap-theme-slate', 'accent': '#475569'},
}


def _safe_date(value, fallback):
    return value or fallback


def _timeline_bounds(plan, phases):
    starts = [p.planned_start for p in phases if p.planned_start]
    ends = [p.planned_end for p in phases if p.planned_end]
    if starts and ends:
        min_start = min(starts)
        max_end = max(ends)
    else:
        min_start = plan.planned_start or date.today()
        max_end = min_start
    total_days = max((max_end - min_start).days + 1, 1)
    return min_start, max_end, total_days


def _build_segments(min_start, max_end, total_days, zoom='month'):
    segments = []
    current = date(min_start.year, min_start.month, 1)
    while current <= max_end:
        if current.month == 12:
            next_month = date(current.year + 1, 1, 1)
        else:
            next_month = date(current.year, current.month + 1, 1)
        quarter_key = (current.year, ((current.month - 1) // 3) + 1)
        if zoom == 'quarter':
            if segments and segments[-1]['quarter_key'] == quarter_key:
                seg_end = min(next_month, max_end)
                width_days = max((seg_end - current).days, 1)
                segments[-1]['width'] += round((width_days / total_days) * 100, 2)
            else:
                seg_end = min(next_month, max_end)
                width_days = max((seg_end - current).days, 1)
                segments.append({
                    'label': f'Q{quarter_key[1]} {quarter_key[0]}',
                    'width': round((width_days / total_days) * 100, 2),
                    'quarter_key': quarter_key,
                })
        else:
            seg_end = min(next_month, max_end)
            width_days = max((seg_end - current).days, 1)
            segments.append({
                'label': current.strftime('%b %Y'),
                'width': round((width_days / total_days) * 100, 2),
                'quarter_key': quarter_key,
            })
        current = next_month
    return segments


def _status_counts(tasks):
    counts = Counter(task.status for task in tasks)
    return [
        {'status': status, 'total': counts[status]}
        for status, _label in RoadmapTask.Status.choices
        if counts[status]
    ]


def _latest_report_for_plan(plan):
    tenant = getattr(plan, 'tenant', None)
    session_id = getattr(plan, 'session_id', None)
    if tenant is None or not session_id:
        return None
    return ReportSnapshot.objects.filter(tenant=tenant, session_id=session_id).first()


class RoadmapPlanListView(TenantAccessMixin, ListView):
    model = RoadmapPlan
    template_name = 'roadmap/plan_list.html'
    context_object_name = 'plans'

    def get_queryset(self):
        tenant = WizardService.get_default_tenant(self.request.user)
        rust_plans = RoadmapRegisterBridge.fetch_list(self.request, tenant)
        if rust_plans is not None:
            self.roadmap_register_source = 'rust_service'
            return rust_plans

        self.roadmap_register_source = 'django'
        return RoadmapPlan.objects.filter(tenant=tenant).prefetch_related('phases__tasks')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['roadmap_register_source'] = getattr(self, 'roadmap_register_source', 'django')
        return context


class RoadmapPlanDetailView(TenantAccessMixin, DetailView):
    model = RoadmapPlan
    template_name = 'roadmap/plan_detail.html'
    context_object_name = 'plan'

    def get_object(self, queryset=None):
        rust_detail = RoadmapRegisterBridge.fetch_detail(
            self.request,
            self.get_tenant(),
            self.kwargs.get(self.pk_url_kwarg),
        )
        if rust_detail is not None:
            self.roadmap_register_source = 'rust_service'
            self.roadmap_detail = rust_detail
            self.check_tenant_access(rust_detail.plan)
            return rust_detail.plan

        self.roadmap_register_source = 'django'
        return super().get_object(queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        plan = self.object
        current_view = self.request.GET.get('view', 'executive')
        if current_view not in {'executive', 'delivery', 'combined', 'boardroom'}:
            current_view = 'executive'
        current_zoom = self.request.GET.get('zoom', 'month')
        if current_zoom not in {'month', 'quarter'}:
            current_zoom = 'month'
        current_theme = self.request.GET.get('theme', 'ocean')
        if current_theme not in THEMES:
            current_theme = 'ocean'

        phases = list(plan.phases.prefetch_related('tasks__incoming_dependencies__predecessor').all())
        min_start, max_end, total_days = _timeline_bounds(plan, phases)

        month_segments = _build_segments(min_start, max_end, total_days, current_zoom)
        if current_zoom == 'quarter':
            grid = []
            offset = 0.0
            for segment in month_segments[:-1]:
                offset += segment['width']
                grid.append(round(offset, 2))
        else:
            grid = [round((idx / max(len(month_segments), 1)) * 100, 2) for idx in range(1, len(month_segments))]

        timeline_rows = []
        for idx, phase in enumerate(phases):
            start = _safe_date(phase.planned_start, min_start)
            end = _safe_date(phase.planned_end, start)
            offset = ((start - min_start).days / total_days) * 100
            width = max((((end - start).days + 1) / total_days) * 100, 7)
            tasks = sorted(list(phase.tasks.all()), key=lambda t: (t.due_date or end, t.priority or '', t.title))
            milestones = []
            visible_milestones = [task for task in tasks if task.due_date][:5]
            for m_idx, task in enumerate(visible_milestones):
                left = ((task.due_date - min_start).days / total_days) * 100
                milestones.append({
                    'left': max(2.0, min(round(left, 2), 98.0)),
                    'title': task.title,
                    'short_title': task.title[:26] + ('…' if len(task.title) > 26 else ''),
                    'date': task.due_date,
                    'priority': task.priority,
                    'slot': 'top' if m_idx % 2 == 0 else 'bottom',
                })
            timeline_rows.append({
                'phase': phase,
                'left': round(offset, 2),
                'width': round(width, 2),
                'color': PHASE_COLORS[idx % len(PHASE_COLORS)],
                'task_count': len(tasks),
                'milestones': milestones,
                'key_tasks': tasks[:3],
                'tasks': tasks,
            })

        rust_detail = getattr(self, 'roadmap_detail', None)
        if rust_detail is not None:
            tasks = sorted(rust_detail.tasks, key=lambda task: (task.due_date or date.max, task.priority or '', task.id))
            dependency_rows = rust_detail.dependencies[:40]
            report = _latest_report_for_plan(plan)
        else:
            tasks = list(
                RoadmapTask.objects.filter(phase__plan=plan)
                .select_related('phase')
                .prefetch_related('incoming_dependencies__predecessor')
                .order_by('due_date', 'priority')
            )
            dependency_rows = list(RoadmapTaskDependency.objects.filter(successor__phase__plan=plan).select_related('predecessor', 'successor')[:40])
            report = plan.session.report_snapshots.first()

        grouped = OrderedDict((choice, []) for choice in RoadmapTask.Status.choices)
        for task in tasks:
            grouped[(task.status, task.get_status_display())].append(task)

        heatmap_rows = report.domain_scores_json if report else []


        boardroom_top_phases = sorted(timeline_rows, key=lambda row: (-row['task_count'], row['phase'].sort_order))[:4]
        critical_tasks = [task for task in tasks if (task.priority or '').upper() in {'CRITICAL', 'HIGH'}][:6]
        milestone_feed = []
        for row in timeline_rows:
            for milestone in row['milestones'][:2]:
                # Calculate horizontal position for flag markers
                left_pct = round(((milestone['date'] - min_start).days / total_days) * 100, 1) if milestone.get('date') else 50
                left_pct = max(3, min(left_pct, 92))  # Keep flags within visible area
                milestone_feed.append({
                    'phase': row['phase'].name,
                    'title': milestone['title'],
                    'date': milestone['date'],
                    'priority': milestone['priority'] or 'medium',
                    'left_pct': left_pct,
                })
        milestone_feed = sorted(milestone_feed, key=lambda item: item['date'])[:8]

        context.update({
            'timeline_rows': timeline_rows,
            'timeline_grid': grid,
            'timeline_month_segments': month_segments,
            'timeline_start': min_start,
            'timeline_end': max_end,
            'timeline_total_weeks': max(1, round(total_days / 7)),
            'kanban_columns': grouped,
            'status_counts': _status_counts(tasks),
            'dependency_rows': dependency_rows,
            'heatmap_rows': heatmap_rows,
            'report': report,
            'total_tasks': len(tasks),
            'total_dependencies': len(dependency_rows),
            'current_view': current_view,
            'current_zoom': current_zoom,
            'current_theme': current_theme,
            'theme_class': THEMES[current_theme]['shell'],
            'boardroom_top_phases': boardroom_top_phases,
            'critical_tasks': critical_tasks,
            'milestone_feed': milestone_feed,
            'roadmap_register_source': getattr(self, 'roadmap_register_source', 'django'),
        })
        return context


class RoadmapTaskUpdateView(TenantAccessMixin, UpdateView):
    model = RoadmapTask
    form_class = RoadmapTaskUpdateForm
    template_name = 'roadmap/task_form.html'
    tenant_filter_field = 'phase__plan__tenant'

    def get_success_url(self):
        return reverse('roadmap:detail', kwargs={'pk': self.object.phase.plan_id})

    def form_valid(self, form):
        rust_result = RoadmapRegisterBridge.update_task(
            self.request,
            self.get_tenant(),
            self.object.pk,
            form.cleaned_data,
        )
        if rust_result is not None:
            self.object.status = rust_result.task.status
            self.object.planned_start = rust_result.task.planned_start
            self.object.due_date = rust_result.task.due_date
            self.object.owner_role = rust_result.task.owner_role
            self.object.notes = rust_result.task.notes
            return HttpResponseRedirect(reverse('roadmap:detail', kwargs={'pk': rust_result.plan_id}))
        return super().form_valid(form)


class RoadmapKanbanView(TenantAccessMixin, TemplateView):
    template_name = 'roadmap/kanban.html'
    tenant_filter_field = 'tenant'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rust_detail = RoadmapRegisterBridge.fetch_detail(self.request, self.get_tenant(), self.kwargs['pk'])
        if rust_detail is not None:
            self.roadmap_register_source = 'rust_service'
            plan = rust_detail.plan
            self.check_tenant_access(plan)
            tasks = sorted(rust_detail.tasks, key=lambda task: (task.due_date or date.max, task.priority or '', task.id))
        else:
            self.roadmap_register_source = 'django'
            plan = get_object_or_404(self.filter_queryset_for_tenant(RoadmapPlan.objects.all()), pk=self.kwargs['pk'])
            tasks = list(
                RoadmapTask.objects.filter(phase__plan=plan)
                .select_related('phase')
                .prefetch_related('incoming_dependencies__predecessor')
                .order_by('due_date', 'priority')
            )
        grouped = OrderedDict((choice, []) for choice in RoadmapTask.Status.choices)
        for task in tasks:
            grouped[(task.status, task.get_status_display())].append(task)
        context['plan'] = plan
        context['kanban_columns'] = grouped
        context['roadmap_register_source'] = getattr(self, 'roadmap_register_source', 'django')
        return context


class RoadmapPdfView(TenantAccessMixin, View):
    tenant_filter_field = 'tenant'

    def get(self, request, pk):
        rust_detail = RoadmapRegisterBridge.fetch_detail(request, self.get_tenant(), pk)
        if rust_detail is not None:
            plan = rust_detail.plan
            self.check_tenant_access(plan)
            phases = list(plan.phases.all())
            export_tasks = sorted(rust_detail.tasks, key=lambda task: (task.priority or '', task.due_date or date.max, task.id))
        else:
            plan = get_object_or_404(self.filter_queryset_for_tenant(RoadmapPlan.objects.prefetch_related('phases__tasks')), pk=pk)
            phases = list(plan.phases.all())
            export_tasks = list(
                RoadmapTask.objects.filter(phase__plan=plan)
                .prefetch_related('incoming_dependencies__predecessor')
                .order_by('priority', 'due_date')[:14]
            )
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=landscape(A4))
        width, height = landscape(A4)
        margin = 30
        pdf.setTitle(f'Roadmap-{plan.pk}')
        pdf.setFont('Helvetica-Bold', 18)
        pdf.drawString(margin, height - 30, plan.title)
        pdf.setFont('Helvetica', 9)
        pdf.drawString(margin, height - 45, plan.summary[:140])

        min_start, max_end, total_days = _timeline_bounds(plan, phases)

        top = height - 95
        left = margin + 145
        right = width - margin
        track_width = right - left
        lane_height = 34
        header_y = top + 20

        pdf.setFont('Helvetica-Bold', 10)
        pdf.drawString(margin, header_y, 'Phase')
        for i in range(0, 9):
            x = left + (track_width * i / 8)
            pdf.setStrokeColor(colors.HexColor('#d7e3f4'))
            pdf.line(x, top + 10, x, top - (lane_height * len(phases)) - 10)
            if i < 8:
                pdf.setFillColor(colors.HexColor('#4f6b8a'))
                pdf.setFont('Helvetica', 7)
                label_date = min_start if i == 0 else min_start.fromordinal(min_start.toordinal() + int(total_days * i / 8))
                pdf.drawString(x + 2, top + 14, label_date.strftime('%d.%m.%y'))

        for idx, phase in enumerate(phases):
            row_y = top - idx * lane_height
            color = colors.HexColor(PHASE_COLORS[idx % len(PHASE_COLORS)])
            start = _safe_date(phase.planned_start, min_start)
            end = _safe_date(phase.planned_end, start)
            offset = ((start - min_start).days / total_days) * track_width
            width_bar = max((((end - start).days + 1) / total_days) * track_width, 84)
            pdf.setFillColor(colors.black)
            pdf.setFont('Helvetica-Bold', 8)
            pdf.drawString(margin, row_y + 6, phase.name[:26])
            pdf.setFont('Helvetica', 7)
            pdf.drawString(margin, row_y - 3, f'{phase.duration_weeks} Wochen')
            pdf.setFillColor(colors.HexColor('#edf3fb'))
            pdf.roundRect(left, row_y - 10, track_width, 20, 6, fill=1, stroke=0)
            pdf.setFillColor(color)
            pdf.roundRect(left + offset, row_y - 10, width_bar, 20, 6, fill=1, stroke=0)
            pdf.setFillColor(colors.white)
            pdf.setFont('Helvetica-Bold', 8)
            pdf.drawString(left + offset + 6, row_y + 2, phase.name[:35])
            pdf.setFillColor(colors.HexColor('#dc3545'))
            for task in list(phase.tasks.all())[:3]:
                if not task.due_date:
                    continue
                mx = left + (((task.due_date - min_start).days / total_days) * track_width)
                pdf.circle(mx, row_y, 3, fill=1, stroke=0)

        text_y = top - (lane_height * len(phases)) - 35
        pdf.setFillColor(colors.black)
        pdf.setFont('Helvetica-Bold', 11)
        pdf.drawString(margin, text_y, 'Priorisierte Aufgaben und Abhängigkeiten')
        pdf.setFont('Helvetica', 8)
        text_y -= 14
        for task in export_tasks[:14]:
            deps = ', '.join(dep.predecessor.title[:18] for dep in task.incoming_dependencies.all()[:2]) or '-'
            line = f'• {task.title[:45]} | {task.priority or "-"} | fällig: {task.due_date.strftime("%d.%m.%Y") if task.due_date else "-"} | abhängig von: {deps}'
            pdf.drawString(margin, text_y, line[:150])
            text_y -= 12
            if text_y < 40:
                pdf.showPage()
                text_y = height - 40
                pdf.setFont('Helvetica', 8)

        pdf.showPage()
        pdf.save()
        response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="roadmap-{plan.pk}.pdf"'
        return response


class RoadmapPngView(TenantAccessMixin, View):
    tenant_filter_field = 'tenant'

    def get(self, request, pk):
        rust_detail = RoadmapRegisterBridge.fetch_detail(request, self.get_tenant(), pk)
        if rust_detail is not None:
            plan = rust_detail.plan
            self.check_tenant_access(plan)
            phases = list(plan.phases.all())
        else:
            plan = get_object_or_404(self.filter_queryset_for_tenant(RoadmapPlan.objects.prefetch_related('phases__tasks')), pk=pk)
            phases = list(plan.phases.all())
        min_start, max_end, total_days = _timeline_bounds(plan, phases)
        width, height = 2000, 1080
        image = Image.new('RGB', (width, height), '#f0f4fa')
        draw = ImageDraw.Draw(image)
        margin = 56
        left = 400
        right = width - margin
        top = 170
        track_width = right - left
        lane_height = 108

        # Subtle background gradient effect
        for y in range(height):
            r = int(240 + (248 - 240) * y / height)
            g = int(244 + (250 - 244) * y / height)
            b = int(250 + (252 - 250) * y / height)
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        # Title area
        draw.rounded_rectangle((margin - 10, 28, width - margin + 10, 130), radius=28, fill='#ffffff', outline='#dbe4f0')
        draw.text((margin + 16, 44), plan.title, fill='#0f172a')
        draw.text((margin + 16, 86), f'{plan.tenant.name}  ·  {plan.summary[:100]}', fill='#64748b')

        # Month header bubbles
        months = _build_segments(min_start, max_end, total_days, 'month')
        x = left
        for segment in months:
            seg_w = int(track_width * (segment['width'] / 100))
            draw.rounded_rectangle((x, top - 52, x + seg_w - 4, top - 10), radius=16, fill='#ffffff', outline='#e2e8f0')
            draw.text((x + 14, top - 40), segment['label'], fill='#475569')
            x += seg_w

        for idx, phase in enumerate(phases):
            y = top + idx * lane_height
            color = PHASE_COLORS[idx % len(PHASE_COLORS)]
            start = _safe_date(phase.planned_start, min_start)
            end = _safe_date(phase.planned_end, start)
            offset = ((start - min_start).days / total_days) * track_width
            bar_w = max((((end - start).days + 1) / total_days) * track_width, 140)

            # Lane card
            draw.rounded_rectangle((margin, y, right + 10, y + 88), radius=24, fill='#ffffff', outline='#e2e8f0')

            # Accent stripe
            draw.rounded_rectangle((margin + 14, y + 14, margin + 21, y + 74), radius=5, fill=color)

            # Phase label
            draw.text((margin + 36, y + 16), f'Phase {idx + 1}', fill='#94a3b8')
            draw.text((margin + 36, y + 40), phase.name[:28], fill='#0f172a')
            draw.text((margin + 36, y + 62), f'{phase.duration_weeks}W · {phase.tasks.count()} Tasks', fill='#94a3b8')

            # Track background
            draw.rounded_rectangle((left, y + 20, right, y + 68), radius=18, fill='#f1f5f9', outline='#e2e8f0')

            # Phase bar
            bar_end = min(left + offset + bar_w, right)
            draw.rounded_rectangle((left + offset, y + 20, bar_end, y + 68), radius=18, fill=color)

            # Bar text
            draw.text((left + offset + 20, y + 36), phase.name[:32], fill='#ffffff')

            # Milestone flag markers (not red dots)
            for task in list(phase.tasks.all())[:4]:
                if task.due_date:
                    mx = left + (((task.due_date - min_start).days / total_days) * track_width)
                    # Flag triangle
                    draw.polygon([(mx, y + 16), (mx + 12, y + 10), (mx + 12, y + 22)], fill=color, outline='#ffffff')
                    # Stem
                    draw.line([(mx, y + 22), (mx, y + 32)], fill='#94a3b8', width=2)

        out = io.BytesIO()
        image.save(out, format='PNG', quality=95)
        response = HttpResponse(out.getvalue(), content_type='image/png')
        response['Content-Disposition'] = f'attachment; filename="roadmap-{plan.pk}.png"'
        return response
