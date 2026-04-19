from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from .models import Requirement
from .services import RegulatoryMappingService
from .services_rust import RequirementBridge


class RequirementListView(LoginRequiredMixin, ListView):
    model = Requirement
    template_name = 'requirements/requirement_list.html'
    context_object_name = 'requirements'
    paginate_by = 50

    def get_queryset(self):
        rust_library = RequirementBridge.fetch_library(self.request)
        if rust_library is not None:
            self.requirements_source = 'rust_service'
            self.mapping_versions = rust_library.mapping_versions
            return rust_library.requirements

        self.requirements_source = 'django'
        return Requirement.objects.select_related('mapping_version', 'primary_source').order_by('framework', 'code')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if getattr(self, 'requirements_source', 'django') == 'rust_service':
            context['mapping_versions'] = self.mapping_versions
        else:
            context['mapping_versions'] = RegulatoryMappingService.build_version_snapshot()
        context['requirements_source'] = getattr(self, 'requirements_source', 'django')
        return context
