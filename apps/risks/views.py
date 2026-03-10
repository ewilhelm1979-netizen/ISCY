from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView, UpdateView
from apps.wizard.services import WizardService
from .forms import RiskForm
from .models import Risk
from .services import RiskMatrixService


class RiskListView(LoginRequiredMixin, ListView):
    model = Risk
    template_name = 'risks/risk_list.html'
    context_object_name = 'risks'

    def get_queryset(self):
        tenant = WizardService.get_default_tenant(self.request.user)
        if tenant:
            return Risk.objects.filter(tenant=tenant).select_related('owner', 'category', 'process')
        return Risk.objects.none()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        risks = list(self.get_queryset())
        ctx['matrix'] = RiskMatrixService.build_matrix(risks)
        ctx['summary'] = RiskMatrixService.summary(risks)
        ctx['impact_labels'] = ['Unerheblich', 'Gering', 'Mittel', 'Hoch', 'Kritisch']
        ctx['likelihood_labels'] = ['Unwahrscheinlich', 'Selten', 'Moeglich', 'Wahrscheinlich', 'Sehr wahrscheinlich']
        return ctx


class RiskDetailView(LoginRequiredMixin, DetailView):
    model = Risk
    template_name = 'risks/risk_detail.html'
    context_object_name = 'risk'


class RiskCreateView(LoginRequiredMixin, CreateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')

    def form_valid(self, form):
        form.instance.tenant = WizardService.get_default_tenant(self.request.user)
        return super().form_valid(form)


class RiskUpdateView(LoginRequiredMixin, UpdateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')
