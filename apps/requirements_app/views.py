from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from .models import Requirement


class RequirementListView(LoginRequiredMixin, ListView):
    model = Requirement
    template_name = 'requirements/requirement_list.html'
    context_object_name = 'requirements'
    paginate_by = 50
