from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from .forms import ProcessForm
from .models import Process
from .services import ProcessRegisterBridge


class ProcessListView(TenantAccessMixin, ListView):
    model = Process
    template_name = 'processes/process_list.html'
    context_object_name = 'processes'

    def get_queryset(self):
        rust_processes = ProcessRegisterBridge.fetch_list(self.request, self.get_tenant())
        if rust_processes is not None:
            self.process_register_source = 'rust_service'
            return rust_processes

        self.process_register_source = 'django'
        return super().get_queryset().select_related('business_unit', 'owner')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['process_register_source'] = getattr(self, 'process_register_source', 'django')
        return context


class ProcessDetailView(TenantAccessMixin, DetailView):
    model = Process
    template_name = 'processes/process_detail.html'
    context_object_name = 'process'

    def get_object(self, queryset=None):
        rust_process = ProcessRegisterBridge.fetch_detail(
            self.request,
            self.get_tenant(),
            self.kwargs.get(self.pk_url_kwarg),
        )
        if rust_process is not None:
            self.process_register_source = 'rust_service'
            self.check_tenant_access(rust_process)
            return rust_process

        self.process_register_source = 'django'
        return super().get_object(queryset)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        p = self.object
        ctx['process_register_source'] = getattr(self, 'process_register_source', 'django')
        ctx['dimensions'] = [
            ('Dokumentiert', p.documented),
            ('Genehmigt', p.approved),
            ('Kommuniziert', p.communicated),
            ('Implementiert', p.implemented),
            ('Operativ wirksam', p.effective),
            ('Evidenzbasiert', p.evidenced),
            ('Owner zugewiesen', p.owner_id is not None),
            ('Reviewed', p.reviewed_at is not None),
            ('Versioniert', p.reviewed_at is not None and p.documented),
            ('Historisiert', p.reviewed_at is not None),
        ]
        return ctx


class ProcessCreateView(TenantCreateMixin, CreateView):
    model = Process
    form_class = ProcessForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('processes:list')
