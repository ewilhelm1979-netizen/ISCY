from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from .forms import InformationAssetForm
from .models import InformationAsset


class InformationAssetListView(TenantAccessMixin, ListView):
    model = InformationAsset
    template_name = 'assets/asset_list.html'
    context_object_name = 'assets'


class InformationAssetCreateView(TenantCreateMixin, CreateView):
    model = InformationAsset
    form_class = InformationAssetForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assets:list')
