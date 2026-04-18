from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import CreateView, ListView, UpdateView

from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from apps.requirements_app.models import Requirement
from apps.wizard.models import AssessmentSession
from apps.wizard.services import WizardService
from .forms import EvidenceItemForm
from .models import EvidenceItem, RequirementEvidenceNeed
from .services import EvidenceNeedService, EvidenceRegisterBridge


class EvidenceListView(TenantAccessMixin, ListView):
    model = EvidenceItem
    template_name = 'evidence/evidence_list.html'
    context_object_name = 'items'

    def get_queryset(self):
        session_id = self._selected_session()
        rust_overview = EvidenceRegisterBridge.fetch_overview(self.request, self.get_tenant(), session_id=session_id)
        if rust_overview is not None:
            self.evidence_register_source = 'rust_service'
            self.evidence_overview = rust_overview
            return rust_overview.evidence_items

        self.evidence_register_source = 'django'
        qs = super().get_queryset().select_related(
            'session',
            'domain',
            'measure',
            'requirement__mapping_version',
            'requirement__primary_source',
            'owner',
        )
        if session_id:
            qs = qs.filter(session_id=session_id)
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = self.get_tenant()
        selected_session = self._selected_session()
        sessions = AssessmentSession.objects.filter(tenant=tenant) if tenant else []
        overview = getattr(self, 'evidence_overview', None)
        if overview is not None:
            evidence_needs = overview.evidence_needs
            need_summary = overview.need_summary
        else:
            needs = RequirementEvidenceNeed.objects.filter(tenant=tenant).select_related(
                'requirement__mapping_version',
                'requirement__primary_source',
            )
            if selected_session:
                needs = needs.filter(session_id=selected_session)
            need_summary = {
                'open': needs.filter(status=RequirementEvidenceNeed.Status.OPEN).count(),
                'partial': needs.filter(status=RequirementEvidenceNeed.Status.PARTIAL).count(),
                'covered': needs.filter(status=RequirementEvidenceNeed.Status.COVERED).count(),
            }
            evidence_needs = needs[:30]

        evidence_items = context.get('object_list', [])
        context['sessions'] = sessions
        context['selected_session'] = selected_session
        context['items'] = evidence_items
        context['evidence_items'] = evidence_items
        context['needs'] = evidence_needs
        context['evidence_needs'] = evidence_needs
        context['need_summary'] = need_summary
        context['evidence_register_source'] = getattr(self, 'evidence_register_source', 'django')
        return context

    def _selected_session(self):
        return self.request.GET.get('session', '').strip()


class EvidenceNeedSyncView(TenantAccessMixin, UpdateView):
    model = AssessmentSession
    fields = []
    tenant_filter_field = 'tenant'

    def post(self, request, *args, **kwargs):
        session = get_object_or_404(self.get_queryset(), pk=kwargs['pk'])
        EvidenceNeedService.sync_for_session(session)
        return redirect(f"{reverse('evidence:list')}?session={session.id}")


class EvidenceCreateView(TenantCreateMixin, CreateView):
    model = EvidenceItem
    form_class = EvidenceItemForm
    template_name = 'evidence/evidence_form.html'

    def get_initial(self):
        initial = super().get_initial()
        session_id = self.request.GET.get('session')
        requirement_id = self.request.GET.get('requirement')
        if session_id:
            initial['session'] = session_id
        if requirement_id:
            initial['requirement'] = requirement_id
        return initial

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        tenant = WizardService.get_default_tenant(self.request.user)
        session_id = self.request.GET.get('session')
        if tenant:
            form.fields['requirement'].queryset = Requirement.objects.filter(is_active=True).order_by('framework', 'code')
        if session_id:
            form.fields['measure'].queryset = form.fields['measure'].queryset.filter(session_id=session_id)
        return form

    def form_valid(self, form):
        tenant = WizardService.get_default_tenant(self.request.user)
        session_id = self.request.GET.get('session')
        if session_id and not form.instance.session_id:
            form.instance.session = get_object_or_404(AssessmentSession.objects.filter(tenant=tenant), pk=session_id)
        form.instance.owner = self.request.user
        if form.instance.requirement:
            form.instance.linked_requirement = f'{form.instance.requirement.framework} {form.instance.requirement.code}'
        response = super().form_valid(form)
        if form.instance.session_id:
            EvidenceNeedService.sync_for_session(form.instance.session)
        return response

    def get_success_url(self):
        return reverse('evidence:list')


class EvidenceUpdateView(TenantAccessMixin, UpdateView):
    model = EvidenceItem
    form_class = EvidenceItemForm
    template_name = 'evidence/evidence_form.html'

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        tenant = WizardService.get_default_tenant(self.request.user)
        if tenant:
            form.fields['requirement'].queryset = Requirement.objects.filter(is_active=True).order_by('framework', 'code')
        return form

    def form_valid(self, form):
        if form.cleaned_data.get('status') in {'APPROVED', 'REJECTED'}:
            form.instance.reviewed_by = self.request.user
            from django.utils import timezone
            form.instance.reviewed_at = timezone.now()
        if form.instance.requirement:
            form.instance.linked_requirement = f'{form.instance.requirement.framework} {form.instance.requirement.code}'
        response = super().form_valid(form)
        if form.instance.session_id:
            EvidenceNeedService.sync_for_session(form.instance.session)
        return response

    def get_success_url(self):
        return reverse('evidence:list')
