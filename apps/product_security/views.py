from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView

from .models import Product, ProductSecuritySnapshot
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
