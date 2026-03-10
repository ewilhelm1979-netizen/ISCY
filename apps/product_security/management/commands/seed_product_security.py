from datetime import date, timedelta

from django.core.management.base import BaseCommand

from apps.organizations.models import Tenant
from apps.product_security.models import (
    AISystem,
    Component,
    PSIRTCase,
    Product,
    ProductFamily,
    ProductRelease,
    SecurityAdvisory,
    TARA,
    ThreatModel,
    ThreatScenario,
    Vulnerability,
)
from apps.product_security.services import ProductSecurityService


class Command(BaseCommand):
    help = 'Seed demo product-security data for the demo tenant.'

    def handle(self, *args, **options):
        tenant = Tenant.objects.filter(slug='tenant-demo').first() or Tenant.objects.first()
        if not tenant:
            self.stdout.write(self.style.WARNING('No tenant found. Run seed_demo first.'))
            return

        family, _ = ProductFamily.objects.get_or_create(
            tenant=tenant,
            name='Core Platform',
            defaults={'description': 'Digitale Kernprodukte und Services'},
        )
        product, _ = Product.objects.get_or_create(
            tenant=tenant,
            name='ISMS Secure Platform',
            defaults={
                'family': family,
                'code': 'isms-secure-platform',
                'description': 'Demoprodukt fuer Product Security / Secure Development.',
                'has_digital_elements': True,
                'includes_ai': tenant.uses_ai_systems,
                'ot_iacs_context': tenant.ot_iacs_scope,
                'automotive_context': tenant.automotive_scope,
                'support_window_months': 36,
            },
        )
        release, _ = ProductRelease.objects.get_or_create(
            tenant=tenant,
            product=product,
            version='1.0.0',
            defaults={
                'status': ProductRelease.Status.ACTIVE,
                'release_date': date.today() - timedelta(days=30),
                'support_end_date': date.today() + timedelta(days=720),
            },
        )
        web_component, _ = Component.objects.get_or_create(
            tenant=tenant,
            product=product,
            name='Web Application',
            version='1.0.0',
            defaults={'component_type': Component.Type.APPLICATION, 'has_sbom': tenant.sbom_required},
        )
        api_component, _ = Component.objects.get_or_create(
            tenant=tenant,
            product=product,
            name='API Service',
            version='1.0.0',
            defaults={'component_type': Component.Type.SERVICE, 'has_sbom': tenant.sbom_required},
        )
        dependency_component, _ = Component.objects.get_or_create(
            tenant=tenant,
            product=product,
            name='Auth Library',
            version='2.4.1',
            defaults={'component_type': Component.Type.LIBRARY, 'is_open_source': True, 'has_sbom': False},
        )

        threat_model, _ = ThreatModel.objects.get_or_create(
            tenant=tenant,
            product=product,
            release=release,
            name='Initial Threat Model',
            defaults={
                'summary': 'Startpunkt fuer Threat Modeling und Security Reviews.',
                'status': ThreatModel.Status.APPROVED,
            },
        )
        scenario, _ = ThreatScenario.objects.get_or_create(
            tenant=tenant,
            threat_model=threat_model,
            title='API abuse via weak service account',
            defaults={
                'component': api_component,
                'category': ThreatScenario.Category.ELEVATION,
                'attack_path': 'Compromised token -> privileged API endpoint -> tenant data access.',
                'impact': 'Data exposure and unauthorized privileged action.',
                'severity': ThreatScenario.Severity.HIGH,
                'mitigation_status': 'Compensating controls planned',
            },
        )
        TARA.objects.get_or_create(
            tenant=tenant,
            product=product,
            release=release,
            scenario=scenario,
            name='Initial API abuse TARA',
            defaults={
                'summary': 'Risk decision and treatment strategy for privileged API abuse.',
                'attack_feasibility': 3,
                'impact_score': 4,
                'status': TARA.Status.IN_REVIEW,
                'treatment_decision': 'MFA, scope hardening and review of service accounts',
            },
        )
        vuln, _ = Vulnerability.objects.get_or_create(
            tenant=tenant,
            product=product,
            release=release,
            component=dependency_component,
            title='Outdated auth dependency with known vulnerability',
            defaults={
                'cve': 'CVE-2025-12345',
                'severity': Vulnerability.Severity.HIGH,
                'status': Vulnerability.Status.TRIAGED,
                'remediation_due': date.today() + timedelta(days=21),
                'summary': 'Authentication dependency should be upgraded and regression-tested.',
            },
        )
        psirt_case, _ = PSIRTCase.objects.get_or_create(
            tenant=tenant,
            product=product,
            release=release,
            vulnerability=vuln,
            case_id='PSIRT-2026-001',
            defaults={
                'title': 'Dependency vulnerability triage',
                'severity': vuln.severity,
                'status': PSIRTCase.Status.TRIAGE,
                'disclosure_due': date.today() + timedelta(days=30),
                'summary': 'Triage and customer communication preparation for dependency vulnerability.',
            },
        )
        SecurityAdvisory.objects.get_or_create(
            tenant=tenant,
            product=product,
            release=release,
            psirt_case=psirt_case,
            advisory_id='ADV-2026-001',
            defaults={
                'title': 'Security advisory draft for dependency issue',
                'status': SecurityAdvisory.Status.DRAFT,
                'summary': 'Draft advisory for customers once remediation plan is approved.',
            },
        )
        if tenant.uses_ai_systems:
            AISystem.objects.get_or_create(
                tenant=tenant,
                product=product,
                name='Assisted Analysis Module',
                defaults={'risk_classification': AISystem.RiskClass.LIMITED, 'provider': 'Internal / configurable'},
            )
        ProductSecurityService.sync_snapshot_for_tenant(tenant)
        self.stdout.write(self.style.SUCCESS('Product Security demo data seeded.'))
