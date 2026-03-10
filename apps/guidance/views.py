from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import DetailView, TemplateView
from apps.guidance.models import GuidanceStep
from apps.guidance.services import JourneyService


class GuidanceDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'guidance/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = JourneyService.get_default_tenant(self.request.user)
        if not tenant:
            context['error'] = 'Es ist noch kein Tenant vorhanden.'
            return context

        evaluation = JourneyService.evaluate_tenant(tenant, self.request.user)
        context['tenant'] = tenant
        context['state'] = evaluation['state']
        context['todo_items'] = evaluation['todo_items']
        context['next_step_url'] = evaluation['next_step_url']
        context['next_step_label'] = evaluation['next_step_label']
        context['steps'] = GuidanceStep.objects.filter(is_active=True).order_by('sort_order')
        context['phase_progress'] = JourneyService.phase_progress()
        return context


class GuidanceStepDetailView(LoginRequiredMixin, DetailView):
    model = GuidanceStep
    template_name = 'guidance/step_detail.html'
    context_object_name = 'step'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = JourneyService.get_default_tenant(self.request.user)
        context['tenant'] = tenant
        if tenant:
            evaluation = JourneyService.evaluate_tenant(tenant, self.request.user)
            context['state'] = evaluation['state']
            context['next_step_url'] = evaluation['next_step_url']
            context['next_step_label'] = evaluation['next_step_label']
        return context
