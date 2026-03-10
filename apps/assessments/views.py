from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from .forms import ApplicabilityAssessmentForm, AssessmentForm, MeasureForm
from .models import ApplicabilityAssessment, Assessment, Measure


class ApplicabilityListView(LoginRequiredMixin, ListView):
    model = ApplicabilityAssessment
    template_name = 'assessments/applicability_list.html'
    context_object_name = 'items'


class ApplicabilityCreateView(LoginRequiredMixin, CreateView):
    model = ApplicabilityAssessment
    form_class = ApplicabilityAssessmentForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:applicability_list')


class AssessmentListView(LoginRequiredMixin, ListView):
    model = Assessment
    template_name = 'assessments/assessment_list.html'
    context_object_name = 'items'


class AssessmentCreateView(LoginRequiredMixin, CreateView):
    model = Assessment
    form_class = AssessmentForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:list')


class MeasureListView(LoginRequiredMixin, ListView):
    model = Measure
    template_name = 'assessments/measure_list.html'
    context_object_name = 'items'


class MeasureCreateView(LoginRequiredMixin, CreateView):
    model = Measure
    form_class = MeasureForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:measure_list')
