from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView
from .forms import ProcessForm
from .models import Process


class ProcessListView(LoginRequiredMixin, ListView):
    model = Process
    template_name = 'processes/process_list.html'
    context_object_name = 'processes'


class ProcessDetailView(LoginRequiredMixin, DetailView):
    model = Process
    template_name = 'processes/process_detail.html'
    context_object_name = 'process'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        p = self.object
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


class ProcessCreateView(LoginRequiredMixin, CreateView):
    model = Process
    form_class = ProcessForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('processes:list')
