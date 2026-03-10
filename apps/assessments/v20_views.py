"""V20: Views fuer SoA, Audit und Management Review."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views.generic import CreateView, DetailView, FormView, ListView, UpdateView, View

from apps.requirements_app.models import Requirement
from apps.wizard.services import WizardService
from .soa_models import SoADocument, SoAEntry
from .audit_models import Audit, AuditFinding
from .review_models import ManagementReview, ReviewAction
from .v20_forms import (
    SoAEntryForm, AuditForm, AuditFindingForm,
    ManagementReviewForm, ReviewActionForm,
)


# ═══════════════════════ SoA ═══════════════════════

class SoAListView(LoginRequiredMixin, ListView):
    model = SoADocument
    template_name = 'assessments/soa_list.html'
    context_object_name = 'documents'

    def get_queryset(self):
        tenant = WizardService.get_default_tenant(self.request.user)
        return SoADocument.objects.filter(tenant=tenant) if tenant else SoADocument.objects.none()


class SoAGenerateView(LoginRequiredMixin, View):
    """Generiert ein SoA-Dokument aus den aktiven ISO-27001-Requirements."""
    def post(self, request):
        tenant = WizardService.get_default_tenant(request.user)
        if not tenant:
            messages.error(request, 'Kein Tenant zugeordnet.')
            return redirect('assessments:soa_list')
        soa = SoADocument.objects.create(
            tenant=tenant,
            title=f'Statement of Applicability – {tenant.name}',
            version='1.0',
        )
        created = 0
        for req in Requirement.objects.filter(framework='ISO27001', is_active=True):
            SoAEntry.objects.create(
                soa=soa, requirement=req,
                is_applicable=True,
                implementation_status=SoAEntry.ImplementationStatus.NOT_STARTED,
            )
            created += 1
        messages.success(request, f'SoA erstellt mit {created} Annex-A-Controls. Bitte Anwendbarkeit und Status je Control pruefen.')
        return redirect('assessments:soa_detail', pk=soa.pk)


class SoADetailView(LoginRequiredMixin, DetailView):
    model = SoADocument
    template_name = 'assessments/soa_detail.html'
    context_object_name = 'soa'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        entries = self.object.entries.select_related('requirement', 'control_owner').all()
        ctx['entries'] = entries
        ctx['applicable_count'] = sum(1 for e in entries if e.is_applicable)
        ctx['implemented_count'] = sum(1 for e in entries if e.is_applicable and e.implementation_status == 'IMPLEMENTED')
        ctx['excluded_count'] = sum(1 for e in entries if not e.is_applicable)
        return ctx


class SoAEntryUpdateView(LoginRequiredMixin, UpdateView):
    model = SoAEntry
    form_class = SoAEntryForm
    template_name = 'assessments/soa_entry_form.html'

    def get_success_url(self):
        return reverse('assessments:soa_detail', kwargs={'pk': self.object.soa_id})


# ═══════════════════════ Audit ═══════════════════════

class AuditListView(LoginRequiredMixin, ListView):
    model = Audit
    template_name = 'assessments/audit_list.html'
    context_object_name = 'audits'

    def get_queryset(self):
        tenant = WizardService.get_default_tenant(self.request.user)
        return Audit.objects.filter(tenant=tenant) if tenant else Audit.objects.none()


class AuditCreateView(LoginRequiredMixin, CreateView):
    model = Audit
    form_class = AuditForm
    template_name = 'assessments/audit_form.html'

    def form_valid(self, form):
        form.instance.tenant = WizardService.get_default_tenant(self.request.user)
        form.instance.created_by = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('assessments:audit_detail', kwargs={'pk': self.object.pk})


class AuditDetailView(LoginRequiredMixin, DetailView):
    model = Audit
    template_name = 'assessments/audit_detail.html'
    context_object_name = 'audit'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        findings = self.object.findings.select_related('responsible').all()
        ctx['findings'] = findings
        ctx['major_count'] = sum(1 for f in findings if f.severity == 'MAJOR_NC')
        ctx['minor_count'] = sum(1 for f in findings if f.severity == 'MINOR_NC')
        ctx['observation_count'] = sum(1 for f in findings if f.severity == 'OBSERVATION')
        ctx['open_count'] = sum(1 for f in findings if f.status not in ('CLOSED', 'VERIFIED'))
        return ctx


class AuditUpdateView(LoginRequiredMixin, UpdateView):
    model = Audit
    form_class = AuditForm
    template_name = 'assessments/audit_form.html'

    def get_success_url(self):
        return reverse('assessments:audit_detail', kwargs={'pk': self.object.pk})


class FindingCreateView(LoginRequiredMixin, CreateView):
    model = AuditFinding
    form_class = AuditFindingForm
    template_name = 'assessments/finding_form.html'

    def form_valid(self, form):
        form.instance.audit_id = self.kwargs['audit_pk']
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['audit'] = get_object_or_404(Audit, pk=self.kwargs['audit_pk'])
        return ctx

    def get_success_url(self):
        return reverse('assessments:audit_detail', kwargs={'pk': self.kwargs['audit_pk']})


class FindingUpdateView(LoginRequiredMixin, UpdateView):
    model = AuditFinding
    form_class = AuditFindingForm
    template_name = 'assessments/finding_form.html'

    def get_success_url(self):
        return reverse('assessments:audit_detail', kwargs={'pk': self.object.audit_id})


# ═══════════════════════ Management Review ═══════════════════════

class ReviewListView(LoginRequiredMixin, ListView):
    model = ManagementReview
    template_name = 'assessments/review_list.html'
    context_object_name = 'reviews'

    def get_queryset(self):
        tenant = WizardService.get_default_tenant(self.request.user)
        return ManagementReview.objects.filter(tenant=tenant) if tenant else ManagementReview.objects.none()


class ReviewCreateView(LoginRequiredMixin, CreateView):
    model = ManagementReview
    form_class = ManagementReviewForm
    template_name = 'assessments/review_form.html'

    def form_valid(self, form):
        form.instance.tenant = WizardService.get_default_tenant(self.request.user)
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('assessments:review_detail', kwargs={'pk': self.object.pk})


class ReviewDetailView(LoginRequiredMixin, DetailView):
    model = ManagementReview
    template_name = 'assessments/review_detail.html'
    context_object_name = 'review'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['actions'] = self.object.actions.select_related('responsible').all()
        return ctx


class ReviewUpdateView(LoginRequiredMixin, UpdateView):
    model = ManagementReview
    form_class = ManagementReviewForm
    template_name = 'assessments/review_form.html'

    def get_success_url(self):
        return reverse('assessments:review_detail', kwargs={'pk': self.object.pk})


class ReviewActionCreateView(LoginRequiredMixin, CreateView):
    model = ReviewAction
    form_class = ReviewActionForm
    template_name = 'assessments/review_action_form.html'

    def form_valid(self, form):
        form.instance.review_id = self.kwargs['review_pk']
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('assessments:review_detail', kwargs={'pk': self.kwargs['review_pk']})
