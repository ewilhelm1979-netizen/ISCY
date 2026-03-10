from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from apps.organizations.models import BusinessUnit, Supplier, Tenant
from apps.processes.models import Process
from apps.risks.models import Risk
from apps.requirements_app.models import Requirement


class Command(BaseCommand):
    help = 'Seeds demo tenant, admin user and initial demo content.'

    def handle(self, *args, **options):
        tenant, _ = Tenant.objects.get_or_create(
            slug='demo-gmbh',
            defaults={
                'name': 'Demo GmbH',
                'country': 'DE',
                'operation_countries': ['DE', 'AT', 'NL'],
                'description': 'Der Scope umfasst die Softwareentwicklung, zentrale Plattformdienste und den Betrieb geschäftskritischer Systeme.',
                'sector': 'DIGITAL_PROVIDERS',
                'employee_count': 120,
                'annual_revenue_million': 18,
                'balance_sheet_million': 12,
                'critical_services': 'Kundenplattform, Identity Services, Entwicklungsplattform',
                'supply_chain_role': 'Digitaler Dienstleister mit Kunden- und Lieferkettenabhängigkeiten',
                'nis2_relevant': False,
                'kritis_relevant': False,
            },
        )

        User = get_user_model()
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@example.com',
                'role': 'ADMIN',
                'tenant': tenant,
                'is_superuser': True,
                'is_staff': True,
                'first_name': 'Admin',
                'last_name': 'User',
            },
        )
        if created:
            admin_user.set_password('Admin123!')
            admin_user.save()

        for framework, code, title, domain, sector_package, evidence_guidance in [
            ('ISO27001', 'A.5.1', 'Policies for information security', 'Policies', 'ALL', 'Policy, Freigabe, Review-Protokolle und Kommunikationsnachweise hinterlegen.'),
            ('ISO27001', 'A.5.9', 'Inventory of information and other associated assets', 'Asset Management', 'ALL', 'Registerauszug, Owner-Zuordnung und Klassifizierung belegen.'),
            ('ISO27001', 'A.5.23', 'Information security for use of cloud services', 'Supplier & Cloud Security', 'DIGITAL', 'Cloud-Architektur, Shared-Responsibility-Matrix und Sicherheitsnachweise der Provider beifügen.'),
            ('NIS2', 'NIS2-RA-01', 'Risk analysis and information system security policies', 'Governance', 'ALL', 'Risikoanalyse, Management-Freigaben und Sicherheitsrichtlinien beilegen.'),
            ('NIS2', 'NIS2-BC-01', 'Business continuity, backup and disaster recovery', 'Resilience', 'CRITICAL_INFRA', 'Backup-/Restore-Tests, BCM-Pläne und Wiederanlaufnachweise dokumentieren.'),
            ('NIS2', 'NIS2-SC-01', 'Supply chain security', 'Third-Party Risk', 'ALL', 'Lieferantenregister, Kritikalitätsbewertung und Vertragsanforderungen beilegen.'),
        ]:
            Requirement.objects.get_or_create(
                framework=framework,
                code=code,
                defaults={
                    'title': title,
                    'domain': domain,
                    'description': title,
                    'guidance': 'Initial demo requirement',
                    'sector_package': sector_package,
                    'evidence_guidance': evidence_guidance,
                    'evidence_examples': 'Policy, Screenshot, Export, Review-Protokoll, Ticket oder Auditnachweis.',
                },
            )

        for name in ['Geschäftsführung', 'Informationssicherheit und Compliance', 'IT-Betrieb', 'Softwareentwicklung', 'Backoffice-Betrieb']:
            BusinessUnit.objects.get_or_create(tenant=tenant, name=name)

        for name in ['Secure Software Development Lifecycle', 'Incident Management', 'Lieferantenbewertung']:
            Process.objects.get_or_create(
                tenant=tenant,
                name=name,
                defaults={'description': 'Demoprozess', 'status': Process.Status.PARTIAL, 'documented': True, 'implemented': True},
            )

        for name in ['Cloud Hosting Provider', 'Identity Provider', 'Managed SOC Provider']:
            Supplier.objects.get_or_create(
                tenant=tenant,
                name=name,
                defaults={'service_description': 'Demolieferant aus dem Seed', 'criticality': 'HIGH'},
            )

        Risk.objects.get_or_create(
            tenant=tenant,
            title='Unvollständige Nachweise für sichere Entwicklung und Reviews',
            defaults={
                'description': 'Reviews finden statt, sind aber noch nicht konsistent dokumentiert.',
                'impact': 4,
                'likelihood': 3,
                'status': Risk.Status.IDENTIFIED,
                'treatment_strategy': Risk.Treatment.MITIGATE,
                'treatment_plan': 'Checklisten, Freigaben und Evidenzablage einführen.',
            },
        )

        self.stdout.write(self.style.SUCCESS('Demo data created. Login: admin / Admin123!'))
