from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView, UpdateView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from .forms import RiskForm
from .models import Risk
from .services import RiskMatrixService, RiskRegisterBridge


class RiskListView(TenantAccessMixin, ListView):
    model = Risk
    template_name = 'risks/risk_list.html'
    context_object_name = 'risks'

    def get_queryset(self):
        rust_risks = RiskRegisterBridge.fetch_list(self.request, self.get_tenant())
        if rust_risks is not None:
            self.risk_register_source = 'rust_service'
            return rust_risks

        self.risk_register_source = 'django'
        return super().get_queryset().select_related('owner', 'category', 'process', 'asset')

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        risks = list(ctx.get('risks', []))
        ctx['risk_register_source'] = getattr(self, 'risk_register_source', 'django')
        ctx['matrix'] = RiskMatrixService.build_matrix(risks)
        ctx['summary'] = RiskMatrixService.summary(risks)
        ctx['impact_labels'] = ['Unerheblich', 'Gering', 'Mittel', 'Hoch', 'Kritisch']
        ctx['likelihood_labels'] = ['Unwahrscheinlich', 'Selten', 'Moeglich', 'Wahrscheinlich', 'Sehr wahrscheinlich']
        return ctx


class RiskDetailView(TenantAccessMixin, DetailView):
    model = Risk
    template_name = 'risks/risk_detail.html'
    context_object_name = 'risk'

    def get_object(self, queryset=None):
        rust_risk = RiskRegisterBridge.fetch_detail(
            self.request,
            self.get_tenant(),
            self.kwargs.get(self.pk_url_kwarg),
        )
        if rust_risk is not None:
            self.risk_register_source = 'rust_service'
            self.check_tenant_access(rust_risk)
            return rust_risk

        self.risk_register_source = 'django'
        return super().get_object(queryset)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['risk_register_source'] = getattr(self, 'risk_register_source', 'django')
        return ctx


class RiskCreateView(TenantCreateMixin, CreateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')

    def form_valid(self, form):
        rust_risk = RiskRegisterBridge.create_from_form(self.request, self.get_tenant(), form)
        if rust_risk is not None:
            return redirect(str(self.success_url))
        return super().form_valid(form)


class RiskUpdateView(TenantAccessMixin, UpdateView):
    model = Risk
    form_class = RiskForm
    template_name = 'risks/risk_form.html'
    success_url = reverse_lazy('risks:list')

    def form_valid(self, form):
        rust_risk = RiskRegisterBridge.update_from_form(
            self.request,
            self.get_tenant(),
            form.instance.pk,
            form,
        )
        if rust_risk is not None:
            return redirect(str(self.success_url))
        return super().form_valid(form)
