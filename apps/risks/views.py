from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView, UpdateView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from apps.wizard.services import WizardService
from .forms import RiskForm
from .models import Risk
from .services import RiskMatrixService


class RiskListView(TenantAccessMixin, ListView):
    model = Risk
    template_name = 'risks/risk_list.html'
    context_object_name = 'risks'

    def get_queryset(self):
        return super().get_queryset().select_related('owner', 'category', 'process')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        risks = list(self.get_queryset())
        ctx['matrix'] = RiskMatrixService.build_matrix(risks)
        ctx['summary'] = RiskMatrixService.summary(risks)
        ctx['impact_labels'] = ['Unerheblich', 'Gering', 'Mittel', 'Hoch', 'Kritisch']
        ctx['likelihood_labels'] = ['Unwahrscheinlich', 'Selten', 'Moeglich', 'Wahrscheinlich', 'Sehr wahrscheinlich']
        return ctx


class RiskDetailView(TenantAccessMixin, DetailView):
    model = Risk
    template_name = 'risks/risk_detail.html'
    context_object_name = 'risk'


class RiskCreateView(TenantCreateMixin, CreateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')

class RiskUpdateView(TenantAccessMixin, UpdateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')
