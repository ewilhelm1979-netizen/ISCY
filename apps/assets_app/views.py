
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from .forms import InformationAssetForm
from .models import InformationAsset


class InformationAssetListView(LoginRequiredMixin, ListView):
    model = InformationAsset
    template_name = 'assets/asset_list.html'
    context_object_name = 'assets'


class InformationAssetCreateView(LoginRequiredMixin, CreateView):
    model = InformationAsset
    form_class = InformationAssetForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assets:list')
