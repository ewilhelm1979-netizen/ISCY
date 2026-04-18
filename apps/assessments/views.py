from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView
from apps.core.mixins import TenantAccessMixin, TenantCreateMixin
from .forms import ApplicabilityAssessmentForm, AssessmentForm, MeasureForm
from .models import ApplicabilityAssessment, Assessment, Measure
from .services import AssessmentRegisterBridge


class ApplicabilityListView(TenantAccessMixin, ListView):
    model = ApplicabilityAssessment
    template_name = 'assessments/applicability_list.html'
    context_object_name = 'items'

    def get_queryset(self):
        rust_items = AssessmentRegisterBridge.fetch_applicability(self.request, self.get_tenant())
        if rust_items is not None:
            self.assessment_register_source = 'rust_service'
            return rust_items

        self.assessment_register_source = 'django'
        return super().get_queryset()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment_register_source'] = getattr(self, 'assessment_register_source', 'django')
        return context


class ApplicabilityCreateView(TenantCreateMixin, CreateView):
    model = ApplicabilityAssessment
    form_class = ApplicabilityAssessmentForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:applicability_list')


class AssessmentListView(TenantAccessMixin, ListView):
    model = Assessment
    template_name = 'assessments/assessment_list.html'
    context_object_name = 'items'

    def get_queryset(self):
        rust_items = AssessmentRegisterBridge.fetch_assessments(self.request, self.get_tenant())
        if rust_items is not None:
            self.assessment_register_source = 'rust_service'
            return rust_items

        self.assessment_register_source = 'django'
        return super().get_queryset().select_related('process', 'requirement', 'owner')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment_register_source'] = getattr(self, 'assessment_register_source', 'django')
        return context


class AssessmentCreateView(TenantCreateMixin, CreateView):
    model = Assessment
    form_class = AssessmentForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:list')


class MeasureListView(TenantAccessMixin, ListView):
    model = Measure
    template_name = 'assessments/measure_list.html'
    context_object_name = 'items'

    def get_queryset(self):
        rust_items = AssessmentRegisterBridge.fetch_measures(self.request, self.get_tenant())
        if rust_items is not None:
            self.assessment_register_source = 'rust_service'
            return rust_items

        self.assessment_register_source = 'django'
        return super().get_queryset().select_related('assessment', 'owner')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment_register_source'] = getattr(self, 'assessment_register_source', 'django')
        return context


class MeasureCreateView(TenantCreateMixin, CreateView):
    model = Measure
    form_class = MeasureForm
    template_name = 'shared/form.html'
    success_url = reverse_lazy('assessments:measure_list')
