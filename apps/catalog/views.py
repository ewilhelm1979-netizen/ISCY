from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from .models import AssessmentDomain, AssessmentQuestion
from .services import CatalogBridge


class DomainListView(LoginRequiredMixin, ListView):
    model = AssessmentDomain
    template_name = 'catalog/domain_list.html'
    context_object_name = 'domains'

    def get_queryset(self):
        rust_library = CatalogBridge.fetch_domain_library(self.request)
        if rust_library is not None:
            self.catalog_source = 'rust_service'
            self.catalog_question_count = rust_library.question_count
            return rust_library.domains

        self.catalog_source = 'django'
        return AssessmentDomain.objects.prefetch_related('questions')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if getattr(self, 'catalog_source', 'django') == 'rust_service':
            context['question_count'] = self.catalog_question_count
        else:
            context['question_count'] = AssessmentQuestion.objects.count()
        context['catalog_source'] = getattr(self, 'catalog_source', 'django')
        return context
