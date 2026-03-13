from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from .models import Requirement
from .services import RegulatoryMappingService


class RequirementListView(LoginRequiredMixin, ListView):
    model = Requirement
    template_name = 'requirements/requirement_list.html'
    context_object_name = 'requirements'
    paginate_by = 50

    def get_queryset(self):
        return Requirement.objects.select_related('mapping_version', 'primary_source').order_by('framework', 'code')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['mapping_versions'] = RegulatoryMappingService.build_version_snapshot()
        return context
