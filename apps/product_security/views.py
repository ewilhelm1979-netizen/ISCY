from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, UpdateView

from .forms import ProductSecurityRoadmapTaskUpdateForm, ProductSecurityVulnerabilityUpdateForm
from .models import Product, ProductSecurityRoadmapTask, ProductSecuritySnapshot, Vulnerability
from .services_rust import ProductSecurityBridge
from .services import ProductSecurityService


class ProductListView(LoginRequiredMixin, ListView):
    model = Product
    template_name = 'product_security/product_list.html'
    context_object_name = 'products'

    def get_queryset(self):
        tenant = getattr(self.request, 'tenant', None)
        overview = ProductSecurityBridge.fetch_overview(self.request, tenant)
        self._product_security_overview = overview
        if overview:
            return overview.products
        return Product.objects.for_tenant(tenant).select_related('family')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = getattr(self.request, 'tenant', None)
        overview = getattr(self, '_product_security_overview', None)
        if overview:
            context['matrix'] = overview.matrix
            context['snapshots'] = overview.snapshots
            context['posture'] = overview.posture
            context['product_security_source'] = 'rust_service'
            return context

        context['matrix'] = ProductSecurityService.get_regime_matrix(tenant) if tenant else None
        context['snapshots'] = ProductSecuritySnapshot.objects.for_tenant(tenant).select_related('product')[:10] if tenant else []
        context['posture'] = ProductSecurityService.tenant_posture(tenant) if tenant else None
        context['product_security_source'] = 'django'
        return context


class ProductDetailView(LoginRequiredMixin, DetailView):
    model = Product
    template_name = 'product_security/product_detail.html'
    context_object_name = 'product'

    def get_queryset(self):
        tenant = getattr(self.request, 'tenant', None)
        return Product.objects.for_tenant(tenant).select_related('family')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        product = self.object
        ProductSecurityService.generate_product_roadmap(product)
        detail = ProductSecurityBridge.fetch_detail(self.request, product.tenant, product.id)
        if detail:
            context['object'] = detail.product
            context['product'] = detail.product
            context['components'] = detail.components
            context['releases'] = detail.releases
            context['threat_models'] = detail.threat_models
            context['threat_scenarios'] = detail.threat_scenarios
            context['taras'] = detail.taras
            context['vulnerabilities'] = detail.vulnerabilities
            context['ai_systems'] = detail.ai_systems
            context['psirt_cases'] = detail.psirt_cases
            context['advisories'] = detail.advisories
            context['snapshot'] = detail.snapshot
            context['roadmap'] = detail.roadmap
            context['roadmap_tasks'] = detail.roadmap_tasks
            context['product_security_source'] = 'rust_service'
            return context

        context['components'] = product.components.all().select_related('supplier')
        context['releases'] = product.releases.all()
        context['threat_models'] = product.threat_models.all().prefetch_related('scenarios')
        context['threat_scenarios'] = sum(model.scenarios.count() for model in context['threat_models'])
        context['taras'] = product.taras.all().select_related('scenario', 'release')
        context['vulnerabilities'] = product.vulnerabilities.all().select_related('component', 'release')
        context['ai_systems'] = product.ai_systems.all()
        context['psirt_cases'] = product.psirt_cases.all().select_related('release', 'vulnerability')
        context['advisories'] = product.advisories.all().select_related('release', 'psirt_case')
        context['snapshot'] = product.snapshots.first()
        context['roadmap'] = product.roadmaps.first()
        context['roadmap_tasks'] = context['roadmap'].tasks.all() if context['roadmap'] else []
        context['product_security_source'] = 'django'
        return context


class ProductRoadmapView(LoginRequiredMixin, TemplateView):
    template_name = 'product_security/roadmap_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = getattr(self.request, 'tenant', None)
        product = get_object_or_404(Product.objects.for_tenant(tenant), pk=self.kwargs['pk'])
        roadmap = ProductSecurityService.generate_product_roadmap(product)
        detail = ProductSecurityBridge.fetch_roadmap(self.request, product.tenant, product.id)
        if detail:
            phase_order = [
                ('GOVERNANCE', 'Governance'),
                ('MODELING', 'Threat Modeling / TARA'),
                ('DELIVERY', 'Secure Delivery'),
                ('RESPONSE', 'PSIRT / Response'),
                ('COMPLIANCE', 'Regulatory Readiness'),
            ]
            grouped = {
                (phase_code, phase_label): [
                    task for task in detail.tasks if task.phase == phase_code
                ]
                for phase_code, phase_label in phase_order
            }
            context.update({
                'product': detail.product,
                'roadmap': detail.roadmap,
                'grouped_tasks': grouped,
                'snapshot': detail.snapshot,
                'product_security_source': 'rust_service',
            })
            return context

        tasks = roadmap.tasks.all().order_by('phase', 'priority', 'title')
        grouped = {}
        for phase_code, phase_label in roadmap.tasks.model.Phase.choices:
            grouped[(phase_code, phase_label)] = [task for task in tasks if task.phase == phase_code]
        context.update({
            'product': product,
            'roadmap': roadmap,
            'grouped_tasks': grouped,
            'snapshot': product.snapshots.first(),
            'product_security_source': 'django',
        })
        return context


class ProductSecurityRoadmapTaskUpdateView(LoginRequiredMixin, UpdateView):
    model = ProductSecurityRoadmapTask
    form_class = ProductSecurityRoadmapTaskUpdateForm
    template_name = 'product_security/roadmap_task_form.html'
    context_object_name = 'task'

    def get_queryset(self):
        tenant = getattr(self.request, 'tenant', None)
        return ProductSecurityRoadmapTask.objects.for_tenant(tenant).select_related('roadmap__product')

    def get_success_url(self):
        return reverse('product_security:roadmap', kwargs={'pk': self.object.roadmap.product_id})

    def form_valid(self, form):
        rust_result = ProductSecurityBridge.update_roadmap_task(
            self.request,
            getattr(self.request, 'tenant', None),
            self.object.pk,
            form.cleaned_data,
        )
        if rust_result is not None:
            self.object.status = rust_result.task.status
            self.object.priority = rust_result.task.priority
            self.object.owner_role = rust_result.task.owner_role
            self.object.due_in_days = rust_result.task.due_in_days
            self.object.dependency_text = rust_result.task.dependency_text
            return HttpResponseRedirect(
                reverse('product_security:roadmap', kwargs={'pk': rust_result.product_id})
            )
        return super().form_valid(form)


class ProductSecurityVulnerabilityUpdateView(LoginRequiredMixin, UpdateView):
    model = Vulnerability
    form_class = ProductSecurityVulnerabilityUpdateForm
    template_name = 'product_security/vulnerability_form.html'
    context_object_name = 'vulnerability'

    def get_queryset(self):
        tenant = getattr(self.request, 'tenant', None)
        return Vulnerability.objects.for_tenant(tenant).select_related('product', 'release', 'component')

    def get_success_url(self):
        return reverse('product_security:detail', kwargs={'pk': self.object.product_id})

    def form_valid(self, form):
        rust_result = ProductSecurityBridge.update_vulnerability(
            self.request,
            getattr(self.request, 'tenant', None),
            self.object.pk,
            form.cleaned_data,
        )
        if rust_result is not None:
            self.object.severity = rust_result.vulnerability.severity
            self.object.status = rust_result.vulnerability.status
            self.object.remediation_due = rust_result.vulnerability.remediation_due
            self.object.summary = rust_result.vulnerability.summary
            return HttpResponseRedirect(
                reverse('product_security:detail', kwargs={'pk': rust_result.product_id})
            )
        return super().form_valid(form)
