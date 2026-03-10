"""Seed ISO 27001, NIS2 and product-security related requirements."""

from django.core.management.base import BaseCommand
from apps.requirements_app.models import Requirement


class Command(BaseCommand):
    help = 'Seed ISO 27001:2022 Annex A, NIS2 and product-security requirements.'

    def handle(self, *args, **options):
        iso_reqs = [
            ('A.5.1', 'Informationssicherheitsrichtlinien', 'Governance', 'Richtlinien fuer Informationssicherheit muessen definiert, genehmigt und kommuniziert werden.', 'Freigegebene IS-Policy, Kommunikationsnachweis', 'ALL'),
            ('A.5.2', 'Rollen und Verantwortlichkeiten', 'Governance', 'Rollen und Verantwortlichkeiten fuer Informationssicherheit muessen zugewiesen und kommuniziert werden.', 'RACI-Matrix, Stellenbeschreibungen', 'ALL'),
            ('A.5.9', 'Inventar der Informationen und zugehoeriger Assets', 'Asset-Management', 'Ein Inventar der Informationen und zugehoeriger Assets muss gefuehrt werden.', 'Asset-Register, Prozessregister', 'ALL'),
            ('A.5.12', 'Klassifizierung von Informationen', 'Asset-Management', 'Informationen muessen nach Schutzbedarf klassifiziert werden.', 'Klassifizierungsschema, Handhabungsrichtlinie', 'ALL'),
            ('A.5.15', 'Zugangssteuerung', 'IAM', 'Regeln fuer physischen und logischen Zugang muessen basierend auf Geschaeftsanforderungen definiert werden.', 'Zugangsrichtlinie, Berechtigungskonzept', 'ALL'),
            ('A.5.19', 'Informationssicherheit in Lieferantenbeziehungen', 'Lieferkette', 'Anforderungen an die Sicherheit muessen in Lieferantenbeziehungen beruecksichtigt werden.', 'Lieferantenbewertung, Vertragsklauseln', 'ALL'),
            ('A.5.23', 'Informationssicherheit bei Cloud-Diensten', 'Cloud', 'Prozesse fuer Beschaffung, Nutzung und Beendigung von Cloud-Diensten muessen definiert werden.', 'Cloud-Register, Shared-Responsibility-Dokumentation', 'DIGITAL'),
            ('A.5.24', 'Incident Management Planung', 'Incident', 'Vorgehensweisen fuer das Management von Informationssicherheitsereignissen muessen geplant werden.', 'IR-Plan, Eskalationsmatrix', 'ALL'),
            ('A.5.29', 'Informationssicherheit bei Stoerungen', 'BCM', 'Anforderungen an die Aufrechterhaltung der IS bei Stoerungen muessen geplant werden.', 'BIA, BCM-Plan', 'ALL'),
            ('A.5.31', 'Rechtliche und regulatorische Anforderungen', 'Governance', 'Anwendbare Anforderungen muessen identifiziert und dokumentiert werden.', 'Rechtsregister, Compliance-Status', 'ALL'),
            ('A.5.37', 'Dokumentierte Betriebsablaeufe', 'Dokumentation', 'Betriebsablaeufe muessen dokumentiert und zugaenglich gemacht werden.', 'Betriebshandbuch, SOPs', 'ALL'),
            ('A.6.3', 'Informationssicherheitsbewusstsein und -schulung', 'Awareness', 'Alle Mitarbeitenden muessen geschult werden.', 'Schulungsnachweise, Awareness-Plan', 'ALL'),
            ('A.7.2', 'Physische Zugangssteuerung', 'Physische Sicherheit', 'Sichere Bereiche muessen durch angemessene Zugangskontrollen geschuetzt werden.', 'Zutrittsprotokoll, Zugangsrichtlinie', 'ALL'),
            ('A.8.2', 'Privilegierte Zugriffsrechte', 'IAM', 'Zuweisung und Nutzung privilegierter Rechte muss eingeschraenkt und gesteuert werden.', 'PAM-Konzept, privilegierte Konten-Liste', 'ALL'),
            ('A.8.5', 'Sichere Authentifizierung', 'IAM', 'Sichere Authentifizierungsverfahren muessen eingerichtet werden.', 'MFA-Nachweis, Passwort-Policy', 'ALL'),
            ('A.8.7', 'Schutz gegen Schadsoftware', 'Cyber', 'Schutz gegen Schadsoftware muss implementiert werden.', 'Endpoint-Protection-Nachweis', 'ALL'),
            ('A.8.8', 'Management technischer Schwachstellen', 'Cyber', 'Informationen ueber technische Schwachstellen muessen beschafft und bewertet werden.', 'Schwachstellen-Reports, Patch-Status', 'ALL'),
            ('A.8.13', 'Sicherung von Informationen', 'BCM', 'Sicherungskopien muessen erstellt und regelmaessig getestet werden.', 'Backup-Konzept, Restore-Tests', 'ALL'),
            ('A.8.15', 'Protokollierung', 'Detect', 'Aktivitaeten, Ausnahmen und IS-Ereignisse muessen protokolliert werden.', 'Log-Policy, SIEM-Konfiguration', 'ALL'),
            ('A.8.24', 'Einsatz von Kryptografie', 'Kryptografie', 'Regeln fuer den Einsatz von Kryptografie muessen definiert werden.', 'Kryptografie-Policy, Schluesselmanagement', 'ALL'),
            ('A.8.25', 'Sichere Entwicklung', 'SDLC', 'Regeln fuer die sichere Entwicklung von Software muessen etabliert werden.', 'Secure-SDLC-Richtlinie, Code-Review-Nachweis', 'DIGITAL'),
            ('A.8.29', 'Sicherheitstests in Entwicklung und Abnahme', 'SDLC', 'Sicherheitstests sollen in Entwicklung und Abnahme beruecksichtigt werden.', 'SAST/DAST/Pentest-Nachweise', 'DIGITAL'),
            ('A.8.32', 'Aenderungsmanagement', 'SDLC', 'Aenderungen muessen kontrolliert durchgefuehrt werden.', 'Change-Prozess, Freigabeprotokolle', 'ALL'),
        ]
        for code, title, domain, desc, evidence, pkg in iso_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.ISO27001,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        nis2_reqs = [
            ('NIS2-21-2a', 'Risikoanalyse und Sicherheit von Informationssystemen', 'Governance', 'Betroffene Einrichtungen muessen ein Konzept fuer Risikoanalyse und Sicherheit ihrer Informationssysteme einfuehren.', 'Risikoanalyse-Methodik, Risikobericht', 'ALL'),
            ('NIS2-21-2b', 'Bewertung der Wirksamkeit von Risikomanagemassnahmen', 'Governance', 'Die Wirksamkeit der getroffenen Massnahmen muss bewertet werden.', 'Wirksamkeitsbericht, KPI-Dashboard', 'ALL'),
            ('NIS2-21-2c', 'Sicherheit der Lieferkette', 'Lieferkette', 'Sicherheitsaspekte in der Lieferkette muessen beruecksichtigt werden.', 'Lieferantenbewertung, Risikoanalyse Lieferkette', 'ALL'),
            ('NIS2-21-2d', 'Sicherheit bei Erwerb, Entwicklung und Wartung', 'SDLC', 'Sicherheit bei Erwerb, Entwicklung und Wartung von Netz- und Informationssystemen.', 'SDLC-Richtlinie, Schwachstellenmanagement', 'ALL'),
            ('NIS2-21-2e', 'Konzepte und Verfahren zur Bewertung der Wirksamkeit', 'Governance', 'Konzepte und Verfahren fuer die Bewertung der Wirksamkeit von Risikomanagemassnahmen.', 'Audit-Bericht, Review-Protokolle', 'ALL'),
            ('NIS2-21-2f', 'Cyberhygiene und Schulung', 'Awareness', 'Grundlegende Verfahren der Cyberhygiene und Schulungen muessen sichergestellt werden.', 'Schulungsnachweise, Awareness-Berichte', 'ALL'),
            ('NIS2-21-2g', 'Kryptografie und Verschluesselung', 'Kryptografie', 'Konzepte und Verfahren fuer den Einsatz von Kryptografie und ggf. Verschluesselung.', 'Kryptografie-Policy, Verschluesselungsnachweis', 'ALL'),
            ('NIS2-21-2h', 'Sicherheit des Personals, Zugangssteuerung und Asset-Management', 'IAM', 'Sicherheit des Personals, Zugangssteuerung und Asset-Management.', 'HR-Security-Policy, Zugangsrichtlinie', 'ALL'),
            ('NIS2-21-2i', 'Multi-Faktor-Authentifizierung', 'IAM', 'Verwendung von MFA oder kontinuierlicher Authentifizierung.', 'MFA-Nachweis, Konfigurationsdokumentation', 'ALL'),
            ('NIS2-21-2j', 'Sichere Kommunikation', 'Kryptografie', 'Gesicherte Sprach-, Video- und Textkommunikation sowie Notfallkommunikation.', 'Kommunikationsrichtlinie, Tool-Inventar', 'ALL'),
            ('NIS2-23', 'Meldepflichten bei erheblichen Sicherheitsvorfaellen', 'Incident', 'Erhebliche Sicherheitsvorfaelle muessen fristgerecht gemeldet werden.', 'Meldeprozess, Kontaktregister BSI/CSIRT', 'ALL'),
        ]
        for code, title, domain, desc, evidence, pkg in nis2_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.NIS2,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        cra_reqs = [
            ('CRA-SEC-BY-DESIGN', 'Secure by Design / Default', 'Product Security', 'Produkte mit digitalen Elementen sollen Security by Design und Security by Default umsetzen.', 'Security Requirements, Architekturentscheidungen, Default-Konfigurationen', 'DIGITAL'),
            ('CRA-VULN-HANDLING', 'Vulnerability Handling', 'PSIRT', 'Schwachstellen muessen aufgenommen, bewertet, behoben und kommuniziert werden.', 'PSIRT-Prozess, Advisorys, Patch-Tracking', 'DIGITAL'),
            ('CRA-SUPPORT-LIFECYCLE', 'Support und Patch-Lifecycle', 'Product Security', 'Support, Updates und Patch-Management muessen ueber den Produktlebenszyklus organisiert werden.', 'Support-Policy, Release-/Patch-Prozess', 'DIGITAL'),
            ('CRA-DOC', 'Technische Security-Dokumentation', 'Product Security', 'Sicherheitsdokumentation und Konformitaetsunterlagen muessen vorbereitet werden.', 'Produktdokumentation, Testnachweise, Compliance-Artefakte', 'DIGITAL'),
        ]
        for code, title, domain, desc, evidence, pkg in cra_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.CRA,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        ai_reqs = [
            ('AI-QMS', 'AI Governance / QMS', 'AI Governance', 'Fuer relevante AI-Systeme muss eine belastbare Governance/QMS-Struktur vorhanden sein.', 'AI-Register, Governance-Dokumente, Rollen', 'DIGITAL'),
            ('AI-RISK-CLASS', 'AI-Risikoklassifizierung', 'AI Governance', 'AI-Systeme und Use Cases muessen klassifiziert und dokumentiert werden.', 'Klassifizierungsdokumente, Use-Case-Register', 'DIGITAL'),
            ('AI-HUMAN-OVERSIGHT', 'Human Oversight und Monitoring', 'AI Governance', 'Oversight, Monitoring und Logging muessen fuer relevante AI-Funktionen geregelt werden.', 'Oversight-Prozess, Logs, Monitoring-Nachweise', 'DIGITAL'),
        ]
        for code, title, domain, desc, evidence, pkg in ai_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.AI_ACT,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        iec_reqs = [
            ('IEC62443-ZONES', 'Zonen / Conduits / Segmentierung', 'Industrial Security', 'OT-/IACS-Systeme sollten in Zonen und Kommunikationsbeziehungen segmentiert werden.', 'Zonen-/Conduit-Modell, Netzplan', 'CRITICAL_INFRA'),
            ('IEC62443-COMP', 'Komponenten- und Integrator-Sicherheit', 'Industrial Security', 'Komponenten, Integrator- und Supplier-Verantwortungen sind sicherheitsbezogen zu steuern.', 'Komponentenregister, Integrationsvorgaben', 'CRITICAL_INFRA'),
            ('IEC62443-SL', 'Security Levels und industrielle Schutzanforderungen', 'Industrial Security', 'Sicherheitsniveaus und industrielle Schutzanforderungen sind zu definieren.', 'Security-Level-Konzept, Schutzbedarfsanalyse', 'CRITICAL_INFRA'),
        ]
        for code, title, domain, desc, evidence, pkg in iec_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.IEC62443,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        auto_reqs = [
            ('21434-TARA', 'Threat Analysis and Risk Assessment', 'Automotive Security', 'Eine TARA ist fuer relevante Fahrzeug-/E/E-/Software-Kontexte erforderlich.', 'TARA-Artefakte, Risikoentscheidungen', 'DIGITAL'),
            ('21434-TRACE', 'Cybersecurity-Traceability', 'Automotive Security', 'Cybersecurity-Ziele, Anforderungen, Tests und Nachweise muessen rueckverfolgbar sein.', 'Traceability-Matrix, Testnachweise', 'DIGITAL'),
            ('21434-FIELD', 'Field Monitoring und Updateability', 'Automotive Security', 'Betrieb, Monitoring, Incident Handling und Updates sind ueber den Lebenszyklus abzusichern.', 'Field-Monitoring-Prozess, Update-Konzept', 'DIGITAL'),
        ]
        for code, title, domain, desc, evidence, pkg in auto_reqs:
            Requirement.objects.update_or_create(
                framework=Requirement.Framework.ISO_SAE_21434,
                code=code,
                defaults={
                    'title': title, 'domain': domain, 'description': desc,
                    'evidence_guidance': evidence, 'evidence_required': True,
                    'is_active': True, 'sector_package': pkg,
                },
            )

        counts = {fw: Requirement.objects.filter(framework=fw).count() for fw, _ in Requirement.Framework.choices}
        summary = ', '.join(f'{fw}={count}' for fw, count in counts.items())
        self.stdout.write(self.style.SUCCESS(f'Requirements seeded: {summary}.'))
