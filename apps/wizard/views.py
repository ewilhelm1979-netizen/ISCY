"""Wizard Views V19 – F09 (Tenant-Pruefung), F10 (Audit-Trail), F11 (nicht-destruktives Scope-Update), F14 (Objektautorisierung)."""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import FormView, TemplateView

from apps.catalog.models import AssessmentDomain, AssessmentQuestion
from apps.core.models import AuditLog
from apps.organizations.models import BusinessUnit, Supplier
from apps.processes.models import Process
from apps.reports.models import ReportSnapshot
from apps.roadmap.models import RoadmapPlan
from apps.evidence.models import EvidenceItem
from apps.product_security.services import ProductSecurityService

from .forms import AssessmentLaunchForm, CompanyProfileForm, ScopeCaptureForm
from .models import AssessmentSession
from .services import WizardService


def _require_tenant(request):
    """F09+F14: Stellt sicher dass der User einen Tenant hat."""
    if request.tenant is None:
        raise PermissionDenied('Kein Mandant zugeordnet. Bitte Admin kontaktieren.')
    return request.tenant


def _require_session_access(request, pk):
    """F14: Stellt sicher dass der User Zugriff auf die Session hat."""
    tenant = _require_tenant(request)
    session = get_object_or_404(AssessmentSession, pk=pk)
    if session.tenant_id != tenant.pk:
        raise PermissionDenied('Kein Zugriff auf diese Session.')
    return session


class WizardStartView(LoginRequiredMixin, FormView):
    template_name = 'wizard/start.html'
    form_class = AssessmentLaunchForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = WizardService.get_default_tenant(self.request.user)
        context['tenant'] = tenant
        context['sessions'] = AssessmentSession.objects.filter(tenant=tenant) if tenant else []
        context['latest_report'] = ReportSnapshot.objects.filter(tenant=tenant).first() if tenant else None
        context['sector_context'] = WizardService.get_sector_context(tenant) if tenant else None
        context['country_context'] = WizardService.get_country_context(tenant) if tenant else None
        context['mode_options'] = [WizardService.get_mode_context(choice[0]) for choice in AssessmentSession.Type.choices]
        context['product_matrix'] = ProductSecurityService.get_regime_matrix(tenant) if tenant else None
        return context

    def form_valid(self, form):
        tenant = WizardService.get_default_tenant(self.request.user)
        if not tenant:
            messages.error(self.request, 'Es gibt noch keinen Tenant. Bitte zuerst Demo-Daten seeden oder eine Organisation anlegen.')
            return redirect('organizations:create')

        selected_countries = form.cleaned_data.get('countries') or []
        tenant.sector = form.cleaned_data['sector']
        tenant.operation_countries = selected_countries
        tenant.country = selected_countries[0] if selected_countries else tenant.country
        tenant.save(update_fields=['sector', 'operation_countries', 'country', 'updated_at'])

        session = AssessmentSession.objects.create(
            tenant=tenant,
            assessment_type=form.cleaned_data['assessment_type'],
            started_by=self.request.user,
            status=AssessmentSession.Status.IN_PROGRESS,
            current_step=AssessmentSession.Step.PROFILE,
            progress_percent=10,
        )
        # F10: Audit-Trail
        AuditLog.log(
            request=self.request, action=AuditLog.Action.CREATE,
            entity=session, changes={'assessment_type': session.assessment_type},
        )
        return redirect('wizard:profile', pk=session.pk)


class WizardProfileView(LoginRequiredMixin, View):
    template_name = 'wizard/profile.html'

    def get(self, request, pk):
        session = _require_session_access(request, pk)
        initial_countries = session.tenant.operation_countries or ([session.tenant.country] if session.tenant.country else [])
        form = CompanyProfileForm(instance=session.tenant, initial={'countries': initial_countries})
        return render(request, self.template_name, {
            'session': session,
            'form': form,
            'sector_context': WizardService.get_sector_context(session.tenant),
            'country_context': WizardService.get_country_context(session.tenant),
            'product_matrix': ProductSecurityService.get_regime_matrix(session.tenant),
        })

    def post(self, request, pk):
        session = _require_session_access(request, pk)
        form = CompanyProfileForm(request.POST, instance=session.tenant)
        if form.is_valid():
            tenant = form.save(commit=False)
            selected_countries = form.cleaned_data.get('countries') or []
            tenant.operation_countries = selected_countries
            tenant.country = selected_countries[0] if selected_countries else ''
            tenant.annual_revenue_million = form.cleaned_data.get('annual_revenue_million') or 0
            tenant.balance_sheet_million = form.cleaned_data.get('balance_sheet_million') or 0
            tenant.save()
            # F10: Audit-Trail
            AuditLog.log(
                request=request, action=AuditLog.Action.UPDATE,
                entity=tenant, changes={'sector': tenant.sector, 'countries': selected_countries},
            )
            next_step = WizardService.next_step_after_profile(session)
            session.current_step = next_step
            session.status = AssessmentSession.Status.IN_PROGRESS
            session.save(update_fields=['current_step', 'status', 'updated_at'])
            WizardService.update_progress(session)
            messages.info(request, 'Der ausgewaehlte Sektor beeinflusst nun Betroffenheitsindikation, Schwerpunktdomaenen und Roadmap.')
            if next_step == AssessmentSession.Step.APPLICABILITY:
                return redirect('wizard:applicability', pk=session.pk)
            return redirect('wizard:scope', pk=session.pk)
        return render(request, self.template_name, {
            'session': session,
            'form': form,
            'sector_context': WizardService.get_sector_context(session.tenant),
            'country_context': WizardService.get_country_context(session.tenant),
            'product_matrix': ProductSecurityService.get_regime_matrix(session.tenant),
        })


class WizardApplicabilityView(LoginRequiredMixin, View):
    template_name = 'wizard/applicability.html'

    def get(self, request, pk):
        session = _require_session_access(request, pk)
        questions = AssessmentQuestion.objects.filter(
            question_kind=AssessmentQuestion.Kind.APPLICABILITY
        ).exclude(code='APP_SECTOR').prefetch_related('options')
        existing = {
            answer.question_id: answer.selected_option_id
            for answer in session.answers.filter(question__question_kind=AssessmentQuestion.Kind.APPLICABILITY)
        }
        return render(request, self.template_name, {
            'session': session,
            'questions': questions,
            'existing': existing,
            'sector_context': WizardService.get_sector_context(session.tenant),
            'country_context': WizardService.get_country_context(session.tenant),
        })

    def post(self, request, pk):
        session = _require_session_access(request, pk)
        questions = AssessmentQuestion.objects.filter(
            question_kind=AssessmentQuestion.Kind.APPLICABILITY
        ).exclude(code='APP_SECTOR').prefetch_related('options')
        answers = {}
        for question in questions:
            selected = request.POST.get(f'question_{question.id}')
            if selected:
                answers[question.code] = selected
        WizardService.save_answers(session, answers)
        WizardService.evaluate_applicability(session)
        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            WizardService.generate_results(session)
            messages.success(request, 'Betroffenheitspruefung ausgewertet. Ergebnis und empfohlene naechste Schritte wurden erzeugt.')
            return redirect('wizard:results', pk=session.pk)
        session.current_step = AssessmentSession.Step.SCOPE
        session.save(update_fields=['current_step', 'updated_at'])
        WizardService.update_progress(session)
        return redirect('wizard:scope', pk=session.pk)


class WizardScopeView(LoginRequiredMixin, View):
    template_name = 'wizard/scope.html'

    def get(self, request, pk):
        session = _require_session_access(request, pk)
        business_units = '\n'.join(session.tenant.business_units.values_list('name', flat=True))
        processes = '\n'.join(session.tenant.processes.values_list('name', flat=True))
        suppliers = '\n'.join(session.tenant.suppliers.values_list('name', flat=True))
        form = ScopeCaptureForm(
            initial={
                'scope_statement': session.tenant.description,
                'business_units': business_units,
                'processes': processes,
                'suppliers': suppliers,
            }
        )
        return render(request, self.template_name, {
            'session': session,
            'form': form,
            'sector_context': WizardService.get_sector_context(session.tenant),
            'country_context': WizardService.get_country_context(session.tenant),
        })

    def post(self, request, pk):
        session = _require_session_access(request, pk)
        form = ScopeCaptureForm(request.POST)
        if form.is_valid():
            tenant = session.tenant
            tenant.description = form.cleaned_data['scope_statement']
            tenant.save(update_fields=['description', 'updated_at'])

            # F11: Nicht-destruktives Upsert statt Delete-Recreate
            _upsert_scope_entities(
                tenant, BusinessUnit,
                form.cleaned_data['business_units'],
                lambda name: BusinessUnit(tenant=tenant, name=name),
            )
            _upsert_scope_entities(
                tenant, Process,
                form.cleaned_data['processes'],
                lambda name: Process(
                    tenant=tenant, name=name,
                    description='Aus dem Wizard angelegter Kernprozess',
                    status=Process.Status.MISSING,
                ),
            )
            _upsert_scope_entities(
                tenant, Supplier,
                form.cleaned_data['suppliers'],
                lambda name: Supplier(
                    tenant=tenant, name=name,
                    criticality='HIGH',
                    service_description='Aus dem Wizard angelegter Lieferant',
                ),
            )
            # F10: Audit-Trail
            AuditLog.log(
                request=request, action=AuditLog.Action.UPDATE,
                entity=tenant,
                changes={'scope': 'Scope-Daten aktualisiert (Geschaeftsbereiche, Prozesse, Lieferanten)'},
            )
            session.current_step = AssessmentSession.Step.MATURITY
            session.save(update_fields=['current_step', 'updated_at'])
            WizardService.update_progress(session)
            return redirect('wizard:maturity', pk=session.pk)
        return render(request, self.template_name, {
            'session': session,
            'form': form,
            'sector_context': WizardService.get_sector_context(session.tenant),
            'country_context': WizardService.get_country_context(session.tenant),
        })


def _upsert_scope_entities(tenant, model_class, text_block, create_fn):
    """F11: Merge/Upsert statt Delete-Recreate.

    - Neue Namen werden angelegt.
    - Bestehende Namen bleiben erhalten (inkl. aller Relationen).
    - Namen die nicht mehr in der Liste sind, werden NICHT geloescht,
      um abhaengige Assessments/Evidenzen zu schuetzen.
    """
    new_names = {line.strip() for line in text_block.splitlines() if line.strip()}
    existing_names = set(model_class.objects.filter(tenant=tenant).values_list('name', flat=True))
    to_create = new_names - existing_names
    for name in to_create:
        obj = create_fn(name)
        obj.save()


class WizardMaturityView(LoginRequiredMixin, View):
    template_name = 'wizard/maturity.html'

    def get(self, request, pk):
        session = _require_session_access(request, pk)
        sector_context = WizardService.get_sector_context(session.tenant)
        domains = AssessmentDomain.objects.prefetch_related('questions__options').all().order_by('sort_order')
        if session.assessment_type == AssessmentSession.Type.ISO_READINESS:
            domains = domains.filter(questions__applies_to_iso27001=True).distinct()
        existing = {
            answer.question_id: answer.selected_option_id
            for answer in session.answers.filter(question__question_kind=AssessmentQuestion.Kind.MATURITY)
        }
        return render(request, self.template_name, {
            'session': session,
            'domains': domains,
            'existing': existing,
            'sector_context': sector_context,
            'country_context': WizardService.get_country_context(session.tenant),
        })

    def post(self, request, pk):
        session = _require_session_access(request, pk)
        questions = AssessmentQuestion.objects.filter(question_kind=AssessmentQuestion.Kind.MATURITY)
        if session.assessment_type == AssessmentSession.Type.ISO_READINESS:
            questions = questions.filter(applies_to_iso27001=True)
        answers = {}
        comments = {}
        for question in questions:
            selected = request.POST.get(f'question_{question.id}')
            if selected:
                answers[question.code] = selected
                comments[question.code] = request.POST.get(f'comment_{question.id}', '')
        WizardService.save_answers(session, answers, comments)
        WizardService.generate_results(session)
        # F10: Audit-Trail
        AuditLog.log(
            request=request, action=AuditLog.Action.STATUS_CHANGE,
            entity=session, changes={'status': 'COMPLETED', 'step': 'maturity -> results'},
        )
        messages.success(request, 'Assessment ausgewertet. Massnahmen und Roadmap wurden erzeugt.')
        return redirect('wizard:results', pk=session.pk)


class WizardResultsView(LoginRequiredMixin, TemplateView):
    template_name = 'wizard/results.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        session = _require_session_access(self.request, self.kwargs['pk'])
        report = ReportSnapshot.objects.filter(session=session).first()
        plan = RoadmapPlan.objects.filter(session=session).first()
        context.update(
            {
                'session': session,
                'report': report,
                'plan': plan,
                'domain_scores': session.domain_scores.select_related('domain'),
                'gaps': session.generated_gaps.select_related('domain')[:20],
                'measures': session.generated_measures.select_related('domain')[:20],
                'evidence_count': EvidenceItem.objects.filter(session=session).count(),
                'sector_context': WizardService.get_sector_context(session.tenant),
                'country_context': WizardService.get_country_context(session.tenant),
                'mode_context': WizardService.get_mode_context(session),
                'product_matrix': ProductSecurityService.get_regime_matrix(session.tenant),
            }
        )
        return context
