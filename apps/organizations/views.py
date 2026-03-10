from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from .forms import TenantForm
from .models import Tenant


class TenantListView(LoginRequiredMixin, ListView):
    model = Tenant
    template_name = 'organizations/tenant_list.html'
    context_object_name = 'tenants'


class TenantCreateView(LoginRequiredMixin, CreateView):
    model = Tenant
    form_class = TenantForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('organizations:list')
