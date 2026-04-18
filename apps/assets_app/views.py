from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from .forms import InformationAssetForm
from .models import InformationAsset
from .services import AssetInventoryBridge


class InformationAssetListView(TenantAccessMixin, ListView):
    model = InformationAsset
    template_name = 'assets/asset_list.html'
    context_object_name = 'assets'

    def get_queryset(self):
        rust_assets = AssetInventoryBridge.fetch_list(self.request, self.get_tenant())
        if rust_assets is not None:
            self.asset_inventory_source = 'rust_service'
            return rust_assets

        self.asset_inventory_source = 'django'
        return super().get_queryset().select_related('business_unit', 'owner')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['asset_inventory_source'] = getattr(self, 'asset_inventory_source', 'django')
        return context


class InformationAssetCreateView(TenantCreateMixin, CreateView):
    model = InformationAsset
    form_class = InformationAssetForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assets:list')
