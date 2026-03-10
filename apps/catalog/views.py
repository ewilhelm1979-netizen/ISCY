from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from .models import AssessmentDomain, AssessmentQuestion


class DomainListView(LoginRequiredMixin, ListView):
    model = AssessmentDomain
    template_name = 'catalog/domain_list.html'
    context_object_name = 'domains'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['question_count'] = AssessmentQuestion.objects.count()
        return context
