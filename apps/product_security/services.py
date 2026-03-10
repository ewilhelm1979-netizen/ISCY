from datetime import timedelta

from django.utils import timezone

from apps.catalog.models import AssessmentQuestion
from apps.organizations.sector_catalog import get_sector_definition
from .models import (
    AISystem,
    PSIRTCase,
    Product,
    ProductRelease,
    ProductSecurityRoadmap,
    ProductSecurityRoadmapTask,
    ProductSecuritySnapshot,
    SecurityAdvisory,
    TARA,
    ThreatModel,
    Vulnerability,
)


class ProductSecurityService:
    @staticmethod
    def get_regime_matrix(tenant):
        sector = get_sector_definition(getattr(tenant, 'sector', None))
        develops = bool(getattr(tenant, 'develops_digital_products', False))
        uses_ai = bool(getattr(tenant, 'uses_ai_systems', False))
        ot_scope = bool(getattr(tenant, 'ot_iacs_scope', False))
        automotive_scope = bool(getattr(tenant, 'automotive_scope', False))

        cra = develops
        ai_act = uses_ai
        iec = ot_scope or sector.code in {'ENERGY', 'HYDROGEN', 'DRINKING_WATER', 'WASTEWATER', 'CHEMICALS', 'MANUFACTURING'}
        iso21434 = automotive_scope

        matrix = {
            'cra': {
                'applicable': cra,
                'label': 'CRA',
                'reason': 'Relevant fuer Produkte mit digitalen Elementen und deren Lifecycle.' if cra else 'Derzeit kein klarer Product-with-Digital-Elements-Fokus erkennbar.',
            },
            'ai_act': {
                'applicable': ai_act,
                'label': 'AI Act',
                'reason': 'AI-Systeme/Modelle/Funktionen sind im Scope und erfordern Governance und Dokumentation.' if ai_act else 'Kein AI-System-/Modell-Scope angegeben.',
            },
            'iec62443': {
                'applicable': iec,
                'label': 'IEC 62443',
                'reason': 'OT-/IACS-/Industrie- oder kritische Anlagenkontexte im Scope.' if iec else 'Kein expliziter OT-/IACS-Kontext im Scope.',
            },
            'iso_sae_21434': {
                'applicable': iso21434,
                'label': 'ISO/SAE 21434',
                'reason': 'Automotive-/Fahrzeug-/E/E-Kontext angegeben.' if iso21434 else 'Kein Automotive-/Fahrzeugkontext im Scope.',
            },
        }
        matrix['summary'] = ProductSecurityService.build_summary(tenant, matrix)
        return matrix

    @staticmethod
    def build_summary(tenant, matrix=None):
        matrix = matrix or ProductSecurityService.get_regime_matrix(tenant)
        active = [item['label'] for key, item in matrix.items() if isinstance(item, dict) and item.get('applicable')]
        if active:
            return f'Product Security ist relevant. Aktive Regime/Standards: {", ".join(active)}.'
        if getattr(tenant, 'develops_digital_products', False):
            return 'Es werden digitale Produkte entwickelt; mindestens CRA-/Secure-Development-Readiness sollte bewertet werden.'
        return 'Kein ausgeprägter Product-Security-Scope angegeben. Fokus bleibt auf Enterprise-ISMS.'

    @staticmethod
    def generate_measures(session):
        tenant = session.tenant
        matrix = ProductSecurityService.get_regime_matrix(tenant)
        created_titles = []
        if getattr(tenant, 'develops_digital_products', False):
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='Product Security Governance und Secure Development Lifecycle etablieren',
                description='Secure Development, Security Requirements, Design Reviews, Testing, Release Gates und Lifecycle-Verantwortung fuer digitale Produkte definieren.',
                priority='CRITICAL', effort='LARGE', measure_type='ORGANIZATIONAL', target_phase='Phase 5 – Strukturmassnahmen', owner_role='ISMS Manager', reason='Digitale Produkte/Software im Scope.',
            ))
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='SBOM-/Komponenten- und Dependency-Governance aufbauen',
                description='Komponenten, Bibliotheken, OSS und Supplier-Abhaengigkeiten inventarisieren und auf Produkt-/Release-Kontext mappen.',
                priority='HIGH', effort='MEDIUM', measure_type='TECHNICAL', target_phase='Phase 2 – Transparenz', owner_role='Compliance Manager', reason='Digitale Produkte erfordern Transparenz ueber Komponenten und Dependencies.',
            ))
        if matrix['cra']['applicable']:
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='CRA-Readiness fuer Produkte mit digitalen Elementen vorbereiten',
                description='Lifecycle-Security, Vulnerability Handling, Support-/Patch-Management, Security-Dokumentation und Konformitaetsvorbereitung fuer digitale Produkte konkretisieren.',
                priority='CRITICAL', effort='LARGE', measure_type='DOCUMENTARY', target_phase='Phase 1 – Governance', owner_role='Compliance Manager', reason='CRA Applicability aktiv.',
            ))
        if matrix['ai_act']['applicable']:
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='AI Governance und AI-Act-Readiness aufbauen',
                description='AI-Systeminventar, Risikoklassifizierung, Dokumentation, Logging, Human Oversight und Provider-/Modell-Governance definieren.',
                priority='HIGH', effort='LARGE', measure_type='ORGANIZATIONAL', target_phase='Phase 5 – Strukturmassnahmen', owner_role='Compliance Manager', reason='AI Act Applicability aktiv.',
            ))
        if matrix['iec62443']['applicable']:
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='OT-/IEC-62443-orientierte Security Controls und Segmentierung definieren',
                description='Zonen, Conduits, Security Levels, Integrator-/Supplier-Sicht und industrielle Nachweise fuer OT-/IACS-Kontexte erarbeiten.',
                priority='HIGH', effort='LARGE', measure_type='TECHNICAL', target_phase='Phase 5 – Strukturmassnahmen', owner_role='Security Officer', reason='IEC 62443 Applicability aktiv.',
            ))
        if matrix['iso_sae_21434']['applicable']:
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='Automotive Cybersecurity Engineering nach ISO/SAE 21434 vorbereiten',
                description='TARA, Cybersecurity Goals, Lifecycle-Traceability, Supplier-Einbindung und Field-Monitoring fuer Fahrzeug-/E/E-Kontexte strukturieren.',
                priority='HIGH', effort='LARGE', measure_type='ORGANIZATIONAL', target_phase='Phase 5 – Strukturmassnahmen', owner_role='Security Officer', reason='ISO/SAE 21434 Applicability aktiv.',
            ))
        if getattr(tenant, 'develops_digital_products', False) and not getattr(tenant, 'psirt_defined', False):
            created_titles.append(ProductSecurityService._get_or_create_measure(
                session,
                title='PSIRT-/Vulnerability-Handling-Prozess etablieren',
                description='Schwachstellenaufnahme, Triage, Advisory-/Disclosure-Prozess, Kundenkommunikation und Patch-Steuerung definieren.',
                priority='CRITICAL', effort='MEDIUM', measure_type='ORGANIZATIONAL', target_phase='Phase 4 – Quick Wins', owner_role='Security Officer', reason='Digitale Produkte ohne definierten PSIRT-Prozess.',
            ))
        return [title for title in created_titles if title]

    @staticmethod
    def _get_or_create_measure(session, **defaults):
        measure, _ = session.generated_measures.get_or_create(title=defaults['title'], defaults=defaults)
        return measure.title

    @staticmethod
    def _calc_percent(session, **filters):
        qs = session.answers.filter(question__question_kind=AssessmentQuestion.Kind.MATURITY, **filters).exclude(selected_option__is_na=True)
        total = qs.count()
        if total == 0:
            return 0
        return min(100, int((sum(item.score for item in qs) / (total * 5)) * 100))

    @staticmethod
    def calculate_framework_readiness(session):
        return {
            'cra_readiness_percent': ProductSecurityService._calc_percent(session, question__applies_to_cra=True),
            'ai_act_readiness_percent': ProductSecurityService._calc_percent(session, question__applies_to_ai_act=True),
            'iec62443_readiness_percent': ProductSecurityService._calc_percent(session, question__applies_to_iec62443=True),
            'iso_sae_21434_readiness_percent': ProductSecurityService._calc_percent(session, question__applies_to_iso_sae_21434=True),
        }

    @staticmethod
    def _threat_model_coverage(product):
        releases = max(product.releases.count(), 1)
        approved_count = product.threat_models.filter(status=ThreatModel.Status.APPROVED).count()
        all_count = product.threat_models.count()
        return min(100, int(((approved_count * 1.0) + (all_count * 0.35)) / releases * 100))

    @staticmethod
    def _psirt_readiness(product):
        score = 20
        open_cases = product.psirt_cases.exclude(status=PSIRTCase.Status.CLOSED).count()
        published_advisories = product.advisories.filter(status=SecurityAdvisory.Status.PUBLISHED).count()
        if product.psirt_cases.exists():
            score += 25
        if published_advisories:
            score += 20
        if product.vulnerabilities.exclude(status__in=[Vulnerability.Status.FIXED, Vulnerability.Status.ACCEPTED]).count() == 0:
            score += 20
        if product.components.filter(has_sbom=True).exists():
            score += 15
        if open_cases == 0:
            score += 10
        return min(score, 100)

    @staticmethod
    def sync_snapshot_for_tenant(tenant, session=None):
        matrix = ProductSecurityService.get_regime_matrix(tenant)
        readiness = ProductSecurityService.calculate_framework_readiness(session) if session else {
            'cra_readiness_percent': 0,
            'ai_act_readiness_percent': 0,
            'iec62443_readiness_percent': 0,
            'iso_sae_21434_readiness_percent': 0,
        }
        for product in Product.objects.filter(tenant=tenant):
            open_vulns = product.vulnerabilities.exclude(status__in=[Vulnerability.Status.FIXED, Vulnerability.Status.ACCEPTED])
            ProductSecuritySnapshot.objects.update_or_create(
                tenant=tenant,
                product=product,
                defaults={
                    'cra_applicable': matrix['cra']['applicable'],
                    'ai_act_applicable': matrix['ai_act']['applicable'],
                    'iec62443_applicable': matrix['iec62443']['applicable'],
                    'iso_sae_21434_applicable': matrix['iso_sae_21434']['applicable'],
                    **readiness,
                    'threat_model_coverage_percent': ProductSecurityService._threat_model_coverage(product),
                    'psirt_readiness_percent': ProductSecurityService._psirt_readiness(product),
                    'open_vulnerability_count': open_vulns.count(),
                    'critical_vulnerability_count': open_vulns.filter(severity=Vulnerability.Severity.CRITICAL).count(),
                    'summary': matrix['summary'],
                },
            )
            ProductSecurityService.generate_product_roadmap(product)

    @staticmethod
    def generate_product_roadmap(product):
        snapshot = product.snapshots.first()
        roadmap, _ = ProductSecurityRoadmap.objects.update_or_create(
            tenant=product.tenant,
            product=product,
            defaults={
                'title': f'Product Security Roadmap – {product.name}',
                'summary': 'Aus Product-Security-Regimen, Threat Modeling, Releases und Schwachstellen abgeleitete Roadmap.',
                'generated_from_snapshot': snapshot,
            },
        )
        roadmap.tasks.all().delete()

        def add_task(phase, title, description, priority='HIGH', owner='Product Security Lead', due=45, dependency=''):
            ProductSecurityRoadmapTask.objects.create(
                tenant=product.tenant,
                roadmap=roadmap,
                phase=phase,
                title=title,
                description=description,
                priority=priority,
                owner_role=owner,
                due_in_days=due,
                dependency_text=dependency,
            )

        add_task(
            ProductSecurityRoadmapTask.Phase.GOVERNANCE,
            'Produkt-Scope, Verantwortlichkeiten und Security Sign-off festigen',
            'Produktverantwortung, Release-Governance und Security-Sign-off pro Produkt und Release verbindlich machen.',
            priority='CRITICAL',
            due=21,
        )
        if product.has_digital_elements:
            add_task(
                ProductSecurityRoadmapTask.Phase.COMPLIANCE,
                'CRA-Lifecycle-Readiness und Support-/Patch-Strategie konkretisieren',
                'Supportfenster, Patch-Prozess, Security-Dokumentation und Kundenkommunikation fuer digitale Produkte nachschärfen.',
                priority='CRITICAL',
                owner='Compliance Manager',
                due=30,
            )
        if product.includes_ai:
            add_task(
                ProductSecurityRoadmapTask.Phase.COMPLIANCE,
                'AI Governance, Risikoklassifizierung und Monitoring vertiefen',
                'AI-Systeminventar, Provider-Register, Modellbeobachtung und Human Oversight definieren.',
                owner='AI Governance Lead',
                due=35,
            )
        if product.ot_iacs_context:
            add_task(
                ProductSecurityRoadmapTask.Phase.MODELING,
                'OT-/IEC-62443-Architekturbewertung durchführen',
                'Zonen, Conduits, Segmentierung und Security Level fuer industrielle Kontexte konkretisieren.',
                owner='OT Security Lead',
                due=45,
            )
        if product.automotive_context:
            add_task(
                ProductSecurityRoadmapTask.Phase.MODELING,
                'TARA und Cybersecurity Goals aufsetzen',
                'ISO/SAE-21434-nahe TARA fuer Produkt/Release und kritische Komponenten durchführen.',
                owner='Automotive Security Lead',
                due=40,
            )
        if product.threat_models.count() == 0:
            add_task(
                ProductSecurityRoadmapTask.Phase.MODELING,
                'Threat Model für aktuelles Release erstellen',
                'Mindestens ein Threat Model pro aktivem/nahem Release etablieren.',
                dependency='Governance/Security Sign-off sollte zuerst gesetzt sein.',
            )
        elif product.threat_models.filter(status=ThreatModel.Status.APPROVED).count() == 0:
            add_task(
                ProductSecurityRoadmapTask.Phase.MODELING,
                'Bestehende Threat Models reviewen und freigeben',
                'Vorhandene Threat Models fachlich reviewen und in Release-Gates integrieren.',
                priority='HIGH',
                due=20,
            )
        if product.taras.count() == 0:
            add_task(
                ProductSecurityRoadmapTask.Phase.MODELING,
                'TARA / Risikoentscheidung dokumentieren',
                'Threat Scenarios in konkrete Risikoentscheidungen und Maßnahmen überführen.',
                due=28,
            )

        open_vulns = list(product.vulnerabilities.exclude(status__in=[Vulnerability.Status.FIXED, Vulnerability.Status.ACCEPTED]).order_by('severity', 'title'))
        if open_vulns:
            top_vuln = open_vulns[0]
            ProductSecurityRoadmapTask.objects.create(
                tenant=product.tenant,
                roadmap=roadmap,
                phase=ProductSecurityRoadmapTask.Phase.RESPONSE,
                related_release=top_vuln.release,
                related_vulnerability=top_vuln,
                title='Kritische offene Schwachstellen priorisiert beheben',
                description=f'Priorisierte Behandlung der offenen Schwachstellen, beginnend mit {top_vuln.title}.',
                priority='CRITICAL' if top_vuln.severity == Vulnerability.Severity.CRITICAL else 'HIGH',
                owner_role='PSIRT Lead',
                due_in_days=14 if top_vuln.severity == Vulnerability.Severity.CRITICAL else 30,
                dependency_text='Abhängig von Triage, Fix-Planung und Testfreigabe.',
            )
        if product.psirt_cases.count() == 0:
            add_task(
                ProductSecurityRoadmapTask.Phase.RESPONSE,
                'PSIRT-Case-Workflow einführen',
                'Case IDs, Triage, Disclosure-Fristen und Kundenkommunikation für Product Security Incidents einführen.',
                owner='PSIRT Lead',
                due=21,
            )
        if product.components.filter(has_sbom=False).exists():
            add_task(
                ProductSecurityRoadmapTask.Phase.DELIVERY,
                'SBOM-Abdeckung für Komponenten und Releases erhöhen',
                'Komponenten ohne SBOM identifizieren und Build-/Release-Prozess ergänzen.',
                owner='DevSecOps Lead',
                due=30,
            )
        if product.releases.filter(status__in=[ProductRelease.Status.ACTIVE, ProductRelease.Status.MAINTENANCE]).exists() and not product.advisories.exists():
            add_task(
                ProductSecurityRoadmapTask.Phase.RESPONSE,
                'Security Advisory / Kundentransparenz vorbereiten',
                'Vorlage und Ablauf für Security Advisories und Release Notes mit Security-Bezug aufsetzen.',
                owner='Product Manager',
                due=35,
            )
        return roadmap

    @staticmethod
    def tenant_posture(tenant):
        products = Product.objects.for_tenant(tenant)
        snapshots = ProductSecuritySnapshot.objects.for_tenant(tenant)
        open_vulns = Vulnerability.objects.for_tenant(tenant).exclude(status__in=[Vulnerability.Status.FIXED, Vulnerability.Status.ACCEPTED])
        return {
            'products': products.count(),
            'active_releases': ProductRelease.objects.for_tenant(tenant).filter(status=ProductRelease.Status.ACTIVE).count(),
            'threat_models': ThreatModel.objects.for_tenant(tenant).count(),
            'taras': TARA.objects.for_tenant(tenant).count(),
            'open_vulnerabilities': open_vulns.count(),
            'critical_open_vulnerabilities': open_vulns.filter(severity=Vulnerability.Severity.CRITICAL).count(),
            'psirt_cases_open': PSIRTCase.objects.for_tenant(tenant).exclude(status=PSIRTCase.Status.CLOSED).count(),
            'published_advisories': SecurityAdvisory.objects.for_tenant(tenant).filter(status=SecurityAdvisory.Status.PUBLISHED).count(),
            'avg_threat_model_coverage': int(sum(item.threat_model_coverage_percent for item in snapshots) / snapshots.count()) if snapshots.exists() else 0,
            'avg_psirt_readiness': int(sum(item.psirt_readiness_percent for item in snapshots) / snapshots.count()) if snapshots.exists() else 0,
        }
