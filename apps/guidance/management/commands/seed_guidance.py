from django.core.management.base import BaseCommand
from apps.guidance.models import GuidanceStep


class Command(BaseCommand):
    help = 'Seed default guidance steps'

    def handle(self, *args, **options):
        steps = [
            {
                'code': 'applicability_checked',
                'phase': 'applicability',
                'title': 'Betroffenheitsanalyse durchführen',
                'description': 'Prüfen Sie strukturiert, ob das Unternehmen NIS2- oder KRITIS-nah ist oder vor allem ISO-27001-Readiness benötigt.',
                'why_it_matters': 'Die App darf ISO 27001 nicht als automatischen Ersatz für NIS2 darstellen. Die Betroffenheitsanalyse schafft zuerst Klarheit über die regulatorische Nähe.',
                'required_inputs': 'Sektor, Unternehmensgröße, kritische Dienstleistungen, Lieferkettenrolle, organisatorische Merkmale.',
                'expected_outputs': 'Erste Einordnung in voraussichtlich relevant, möglicherweise relevant oder derzeit nicht direkt relevant.',
                'definition_of_done': 'Mindestens eine Betroffenheitsanalyse wurde dokumentiert.',
                'route_name': 'assessments:applicability_create',
                'cta_label': 'Betroffenheitsanalyse starten',
                'sort_order': 10,
            },
            {
                'code': 'company_scope_defined',
                'phase': 'scope',
                'title': 'ISMS-Scope definieren',
                'description': 'Pflegen Sie Geltungsbereich, Zielbild und organisatorischen Kontext des Mandanten.',
                'why_it_matters': 'Ohne Scope sind Prozess-, Risiko- und Control-Bewertungen nicht belastbar.',
                'required_inputs': 'Unternehmensbeschreibung, Sektor, kritische Leistungen, Standorte, Einheiten.',
                'expected_outputs': 'Dokumentierter ISMS-Geltungsbereich.',
                'definition_of_done': 'Scope ist fachlich beschrieben und im Tenant gepflegt.',
                'route_name': 'organizations:list',
                'cta_label': 'Organisation prüfen',
                'sort_order': 20,
            },
            {
                'code': 'requirements_available',
                'phase': 'mapping',
                'title': 'ISCY Requirement Library bereitstellen',
                'description': 'Stellen Sie sicher, dass ISO-27001- und NIS2-nahe Anforderungen vorhanden sind.',
                'why_it_matters': 'Ohne Anforderungen ist kein Gap-Mapping möglich.',
                'required_inputs': 'Requirement-Katalog.',
                'expected_outputs': 'Verfügbare Requirement-Grundlage.',
                'definition_of_done': 'Requirements sind im System vorhanden.',
                'route_name': 'requirements:list',
                'cta_label': 'Requirements ansehen',
                'sort_order': 30,
            },
            {
                'code': 'initial_processes_captured',
                'phase': 'processes',
                'title': 'Kritische Prozesse erfassen',
                'description': 'Erfassen Sie mindestens die wichtigsten Geschäfts- oder IT-Prozesse.',
                'why_it_matters': 'Prozesse bilden die Basis für Assessments, Risiken und Maßnahmen.',
                'required_inputs': 'Prozessname, Owner, Kritikalität, Beschreibung.',
                'expected_outputs': 'Initiales Prozessregister.',
                'definition_of_done': 'Mindestens 3 Prozesse sind erfasst.',
                'route_name': 'processes:create',
                'cta_label': 'Prozess anlegen',
                'sort_order': 40,
            },
            {
                'code': 'initial_risks_captured',
                'phase': 'assessment',
                'title': 'Erste Risiken dokumentieren',
                'description': 'Erfassen Sie erste Risiken für kritische Prozesse oder Assets.',
                'why_it_matters': 'Risiken helfen bei der Priorisierung von Maßnahmen.',
                'required_inputs': 'Risiko, Beschreibung, Auswirkung, Eintrittswahrscheinlichkeit.',
                'expected_outputs': 'Initiales Risikoregister.',
                'definition_of_done': 'Mindestens 1 Risiko ist erfasst.',
                'route_name': 'risks:create',
                'cta_label': 'Risiko anlegen',
                'sort_order': 50,
            },
            {
                'code': 'initial_assessment_done',
                'phase': 'assessment',
                'title': 'Erstes Assessment durchführen',
                'description': 'Bewerten Sie einen Prozess oder eine Anforderung.',
                'why_it_matters': 'Assessments zeigen, was ausreichend ist und wo echte Gaps bestehen.',
                'required_inputs': 'Bewerteter Prozess, Status, Begründung, ggf. Evidenz.',
                'expected_outputs': 'Erstes dokumentiertes Assessment.',
                'definition_of_done': 'Mindestens 1 Assessment ist vorhanden.',
                'route_name': 'assessments:create',
                'cta_label': 'Assessment anlegen',
                'sort_order': 60,
            },
            {
                'code': 'soc_phishing_playbook_applied',
                'phase': 'measures',
                'title': 'SOC-Playbook für Phishing anwenden',
                'description': (
                    'Bearbeiten Sie gemeldete Phishing-Fälle entlang einer klaren Kette: '
                    'Scope bestimmen, Informationen korrelieren, Gemeinsamkeiten (IOC/TTP) suchen, '
                    'Vorfallstyp bewerten, Verdacht bestätigen, priorisieren, dokumentieren, '
                    'Containment einleiten und bei Bedarf eskalieren.'
                ),
                'why_it_matters': (
                    'Einzel-Alerts werden häufig falsch eingeschätzt. Das Playbook reduziert sowohl '
                    'Unterreaktion (Ausbreitung) als auch Überreaktion (unnötige Eskalation) und schafft '
                    'ein nachvollziehbares Lagebild für SOC, IT und Management.'
                ),
                'required_inputs': (
                    'Mail- und Zustellstatus, Klick-/Interaktionsdaten, Auth-Logs (z. B. Entra ID/M365), '
                    'EDR-/SIEM-/Proxy-/DNS-/Firewall-Daten, Sandbox-Ergebnisse, Threat-Intelligence, '
                    'betroffene User/Hosts/privilegierte Konten, Zeitfenster und mögliche Business-Auswirkung.'
                ),
                'expected_outputs': (
                    'Klassifizierter Incident-Typ (z. B. Spam, Credential Phishing, BEC, Malware Delivery, '
                    'Account Compromise), priorisierte Dringlichkeit, dokumentierte Evidenzkette, '
                    'eingeleitete Containment-Maßnahmen und begründete Eskalationsentscheidung.'
                ),
                'definition_of_done': (
                    'Der Fall ist für Dritte rekonstruierbar dokumentiert: Scope, Korrelationsergebnisse, '
                    'IOC/TTP-Bezüge, Klassifikation, Priorität, Maßnahmen, offene Punkte und klare '
                    'Eskalationsbegründung bzw. Schließungsbegründung sind vorhanden.'
                ),
                'route_name': 'assessments:measure_create',
                'cta_label': 'Incident-Maßnahme erfassen',
                'sort_order': 70,
            },
        ]

        for item in steps:
            GuidanceStep.objects.update_or_create(code=item['code'], defaults=item)

        self.stdout.write(self.style.SUCCESS('Guidance steps seeded.'))
