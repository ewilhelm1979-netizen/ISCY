"""F06: Erweiterter Fragenkatalog (3-5 Fragen pro Domaene statt 1).
   F07: Fragen referenzieren explizit ISO 27001:2022 Annex-A Controls.
"""

from django.core.management.base import BaseCommand
from apps.catalog.models import AssessmentDomain, AssessmentQuestion, AnswerOption, RecommendationRule


MATURITY_OPTIONS = [
    ('missing', 'Nicht vorhanden', 0, 'Es gibt keinen belastbaren Prozess oder Nachweis.'),
    ('informal', 'Informal vorhanden', 1, 'Die Praxis existiert vereinzelt, aber nicht kontrolliert.'),
    ('documented', 'Dokumentiert', 2, 'Der Prozess ist beschrieben, aber noch nicht konsistent umgesetzt.'),
    ('implemented', 'Dokumentiert und umgesetzt', 3, 'Der Prozess ist beschrieben und wird angewendet.'),
    ('evidenced', 'Umgesetzt und nachweisbar', 4, 'Es gibt Nachweise fuer die Umsetzung.'),
    ('reviewed', 'Reviewed / wirksam', 5, 'Der Prozess ist wirksam, reviewed und verbessert.'),
    ('na', 'Nicht relevant', 0, 'Fuer den aktuellen Scope nicht relevant.'),
]


class Command(BaseCommand):
    help = 'Seed assessment domains, questions (F06 expanded), options and recommendation rules.'

    def handle(self, *args, **options):
        domains = [
            ('GOV', 'Governance & Scope', 'Management, Scope und Verantwortlichkeiten.', 10, 10),
            ('PROC', 'Asset- und Prozessmanagement', 'Register, Klassifizierung und Verantwortlichkeiten.', 10, 20),
            ('SUP', 'Lieferkette & Third Parties', 'Dienstleister, Sicherheitsanforderungen und Bewertungen.', 8, 30),
            ('IAM', 'IAM & Notfallkommunikation', 'Zugriffssteuerung, privilegierte Konten und Eskalation.', 9, 40),
            ('CLOUD', 'Cloud & externe Dienste', 'Cloud-Sicherheit und Shared Responsibility.', 8, 50),
            ('SDLC', 'Secure Development & Lifecycle', 'Sichere Entwicklung und Change-Kontrollen.', 10, 60),
            ('CYBER', 'Cyberhygiene & Schwachstellenmanagement', 'Patchen, Hardening und Basis-Security.', 9, 70),
            ('CRYPTO', 'Kryptografie', 'Schluessel, Verschluesselung und Schutz sensibler Daten.', 7, 80),
            ('PHYS', 'Physische Sicherheit', 'Standortschutz und Zugangskontrollen.', 6, 90),
            ('DETECT', 'Logging, Monitoring & Angriffserkennung', 'Zentrales Logging und Alarmierung.', 10, 100),
            ('INC', 'Incident Management', 'Meldewege, Reaktion und Lessons Learned.', 10, 110),
            ('BCM', 'Backup, BCM & Wiederanlauf', 'Backups, Wiederherstellung und Resilienz.', 10, 120),
            ('AWARE', 'Awareness & Schulung', 'Rollenbezogene Schulung und Sensibilisierung.', 7, 130),
            ('DOC', 'Policies, Dokumentation & Reviews', 'Freigaben, Reviews und Versionierung.', 8, 140),
            ('PSM', 'Product Security Management', 'Produkt-Sicherheitsgovernance, CRA und Lifecycle Security.', 10, 150),
            ('PSIRT', 'PSIRT & Vulnerability Handling', 'Schwachstellenaufnahme, Triage, Advisories und Patches.', 10, 160),
            ('AIGOV', 'AI Governance & AI Security', 'AI-Systeminventar, Governance und Nachweise.', 9, 170),
            ('OTSEC', 'Industrial / OT Security', 'IEC-62443-orientierte Industrial Security Controls.', 8, 180),
            ('AUTO', 'Automotive Cybersecurity', 'ISO/SAE-21434-orientierte Automotive Cybersecurity.', 8, 190),
        ]
        domain_map = {}
        for code, name, description, weight, sort_order in domains:
            domain, _ = AssessmentDomain.objects.update_or_create(
                code=code,
                defaults={'name': name, 'description': description, 'weight': weight, 'sort_order': sort_order},
            )
            domain_map[code] = domain

        # --- Applicability-Fragen (unveraendert) ---
        applicability_questions = [
            ('APP_SECTOR', 'Gehoert das Unternehmen zu einem regulierungsnahen oder kritischen Sektor?', 'Sektor und Geschaeftsmodell sind der erste Filter fuer NIS2/KRITIS.', True),
            ('APP_DIGITAL', 'Erbringt das Unternehmen digitale oder kritische Dienste?', 'Digitale Dienste erhoehen die Wahrscheinlichkeit regulatorischer Relevanz.', True),
            ('APP_EMPLOYEES', 'Wie gross ist das Unternehmen gemessen an Mitarbeitenden?', 'Schwellenwerte sind fuer die Einordnung wichtig.', True),
            ('APP_FINANCIAL', 'Wie ist die Groessenordnung von Umsatz bzw. Bilanzsumme?', 'Auch finanzielle Schwellen beeinflussen die Betroffenheit.', True),
            ('APP_SUPPLY', 'Hat das Unternehmen eine kritische Rolle in der Lieferkette anderer regulierter Unternehmen?', 'Auch indirekte Betroffenheit ist fachlich relevant.', True),
        ]
        applicability_options = {
            'APP_SECTOR': [('clear_relevant', 'Ja, eindeutig regulierungsnah/kritisch', 5), ('somewhat_relevant', 'Teilweise / nahe dran', 3), ('not_relevant', 'Nein, derzeit nicht erkennbar', 0)],
            'APP_DIGITAL': [('yes_core', 'Ja, als Kerngeschaeft', 5), ('yes_supporting', 'Ja, als unterstuetzende Leistung', 3), ('no', 'Nein', 0)],
            'APP_EMPLOYEES': [('ge_250', '>= 250', 5), ('ge_50', '50 - 249', 3), ('lt_50', '< 50', 0)],
            'APP_FINANCIAL': [('high', 'Schwellwerte sicher ueberschritten', 5), ('medium', 'vermutlich ueberschritten', 3), ('low', 'eher darunter', 0)],
            'APP_SUPPLY': [('critical', 'Ja, kritische Abhaengigkeiten vorhanden', 4), ('moderate', 'Teilweise relevant', 2), ('none', 'Nein', 0)],
        }
        for index, (code, text, why, nis2) in enumerate(applicability_questions, start=1):
            question, _ = AssessmentQuestion.objects.update_or_create(
                code=code,
                defaults={
                    'domain': None, 'text': text, 'help_text': text, 'why_it_matters': why,
                    'question_kind': AssessmentQuestion.Kind.APPLICABILITY,
                    'wizard_step': AssessmentQuestion.Step.APPLICABILITY,
                    'weight': 10, 'is_required': True, 'applies_to_iso27001': False,
                    'applies_to_nis2': nis2, 'sort_order': index * 10,
                },
            )
            for opt_idx, (slug, label, score) in enumerate(applicability_options[code], start=1):
                AnswerOption.objects.update_or_create(
                    question=question, slug=slug,
                    defaults={'label': label, 'score': score, 'sort_order': opt_idx * 10},
                )

        # --- F06: Erweiterter Maturity-Fragenkatalog (3-5 pro Domaene) ---
        # Format: (code, domain, text, why, annex_a_ref, rec_title, priority, effort, measure_type, target_phase, iso, nis2)
        maturity_questions = [
            # GOV (5 Fragen) – Annex A 5.1-5.4, 5.31
            ('GOV_SCOPE', 'GOV', 'Ist der Geltungsbereich des ISMS definiert und dokumentiert?', 'Ohne klaren Scope sind spaetere Bewertungen unscharf. [A.5.1]', 'ISMS-Scope formalisieren und genehmigen.', 'HIGH', 'SMALL', 'DOCUMENTARY', 'Phase 1 – Governance', True, True),
            ('GOV_ROLES', 'GOV', 'Sind Rollen und Verantwortlichkeiten fuer Informationssicherheit dokumentiert?', 'Verantwortlichkeiten sind Grundlage fuer Wirksamkeit und Auditfaehigkeit. [A.5.2]', 'RACI und Verantwortlichkeiten fuer CISO, Process Owner und Risk Owner festlegen.', 'HIGH', 'SMALL', 'ORGANIZATIONAL', 'Phase 1 – Governance', True, True),
            ('GOV_POLICY', 'GOV', 'Gibt es eine freigegebene Informationssicherheits-Policy?', 'Die Policy ist die Grundlage des ISMS und zeigt Management-Commitment. [A.5.1]', 'IS-Policy erstellen, genehmigen und kommunizieren.', 'CRITICAL', 'SMALL', 'DOCUMENTARY', 'Phase 1 – Governance', True, True),
            ('GOV_MGMT_REVIEW', 'GOV', 'Wird eine regelmaessige Management-Review durchgefuehrt?', 'ISO 27001 Kap. 9.3 fordert regelmaessige Bewertung durch die oberste Leitung.', 'Management-Review-Prozess mit Agenda und Teilnehmern etablieren.', 'HIGH', 'SMALL', 'ORGANIZATIONAL', 'Phase 6 – Audit Readiness', True, False),
            ('GOV_LEGAL', 'GOV', 'Werden rechtliche und regulatorische Anforderungen systematisch erfasst?', 'Compliance-Verpflichtungen muessen identifiziert und bewertet werden. [A.5.31]', 'Register rechtlicher Anforderungen aufbauen und pflegen.', 'MEDIUM', 'MEDIUM', 'DOCUMENTARY', 'Phase 1 – Governance', True, True),

            # PROC (4 Fragen) – Annex A 5.9-5.14
            ('PROC_REGISTER', 'PROC', 'Existiert ein aktuelles Register fuer kritische Prozesse und Assets?', 'Ohne Register sind Risiken und Massnahmen nicht belastbar ableitbar. [A.5.9]', 'Prozess- und Asset-Register vervollstaendigen und klassifizieren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', True, True),
            ('PROC_CLASSIFY', 'PROC', 'Werden Informationen und Assets nach Schutzbedarf klassifiziert?', 'Klassifizierung ist Grundlage fuer angemessene Schutzmassnahmen. [A.5.12, A.5.13]', 'Klassifizierungsschema und Handhabungsrichtlinien einfuehren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', True, True),
            ('PROC_OWNER', 'PROC', 'Sind fuer alle kritischen Assets und Prozesse Verantwortliche benannt?', 'Ownership sichert Pflege, Schutz und Aktualisierung. [A.5.9]', 'Asset-Ownership durchgehend zuweisen und dokumentieren.', 'HIGH', 'SMALL', 'ORGANIZATIONAL', 'Phase 2 – Transparenz', True, True),
            ('PROC_LIFECYCLE', 'PROC', 'Gibt es Regeln fuer den Lebenszyklus von Assets (Beschaffung bis Entsorgung)?', 'Luecken im Lifecycle fuehren zu unkontrollierten Datenbestaenden. [A.5.11]', 'Lifecycle-Richtlinien fuer Assets definieren.', 'MEDIUM', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, False),

            # SUP (3 Fragen) – Annex A 5.19-5.23
            ('SUP_REGISTER', 'SUP', 'Gibt es ein Lieferantenregister mit Kritikalitaetsbewertung?', 'Lieferkettenrisiken sind fuer NIS2 und ISO 27001 relevant. [A.5.19]', 'Lieferanten inventarisieren und nach Kritikalitaet bewerten.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 2 – Transparenz', True, True),
            ('SUP_CONTRACTS', 'SUP', 'Enthalten Lieferantenvertraege Sicherheitsanforderungen?', 'Vertragliche Absicherung ist Grundlage fuer Durchsetzbarkeit. [A.5.20]', 'Sicherheitsklauseln in Mustervertraege aufnehmen.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, True),
            ('SUP_MONITORING', 'SUP', 'Werden kritische Dienstleister regelmaessig ueberwacht und bewertet?', 'Laufende Kontrolle sichert dauerhaftes Sicherheitsniveau. [A.5.22]', 'Lieferanten-Review-Zyklus einfuehren.', 'MEDIUM', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, True),

            # IAM (4 Fragen) – Annex A 5.15-5.18, 8.2-8.5
            ('IAM_MFA', 'IAM', 'Ist MFA fuer kritische Konten und Remote-Zugriffe umgesetzt?', 'MFA ist ein typischer Quick Win mit hoher Wirkung. [A.8.5]', 'MFA-Konzept erstellen und fuer kritische Konten umsetzen.', 'CRITICAL', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('IAM_PRIVILEGED', 'IAM', 'Werden privilegierte Konten gesondert verwaltet und ueberwacht?', 'Privilegierte Zugaenge sind bevorzugtes Angriffsziel. [A.8.2]', 'PAM-Konzept einfuehren und privilegierte Konten inventarisieren.', 'CRITICAL', 'LARGE', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('IAM_LIFECYCLE', 'IAM', 'Gibt es Prozesse fuer Eintritt, Austritt und Rollenwechsel?', 'Identity Lifecycle verhindert verwaiste Konten. [A.5.16, A.5.18]', 'Joiner-Mover-Leaver-Prozess formalisieren.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 2 – Transparenz', True, True),
            ('IAM_ACCESS_REVIEW', 'IAM', 'Werden Zugriffsrechte regelmaessig reviewed?', 'Regelmaessige Reviews verhindern Rechteanhaeufung. [A.5.18]', 'Access-Review-Zyklus (mind. jaehrlich) etablieren.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, False),

            # CLOUD (3 Fragen) – Annex A 5.23, 8.26
            ('CLOUD_INVENTORY', 'CLOUD', 'Sind Cloud-Dienste inventarisiert und mit Sicherheitsvorgaben hinterlegt?', 'Cloud-Nutzung braucht Transparenz und Verantwortungsabgrenzung. [A.5.23]', 'Cloud-Services inventarisieren und Shared Responsibility dokumentieren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', True, True),
            ('CLOUD_CONFIG', 'CLOUD', 'Werden Cloud-Konfigurationen regelmaessig auf Sicherheit geprueft?', 'Fehlkonfigurationen sind eine der haeufigsten Cloud-Schwachstellen. [A.8.26]', 'Cloud Security Posture Reviews einfuehren.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('CLOUD_EXIT', 'CLOUD', 'Gibt es eine Exit-Strategie fuer kritische Cloud-Dienste?', 'Vendor-Lock-in kann Resilienz und Verfuegbarkeit gefaehrden.', 'Exit-Strategien und Datenmigration fuer kritische Cloud-Dienste planen.', 'MEDIUM', 'SMALL', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, False),

            # SDLC (3 Fragen) – Annex A 8.25-8.31
            ('SDLC_SECURE', 'SDLC', 'Gibt es Anforderungen fuer sichere Softwareentwicklung und Code Reviews?', 'Fuer Softwareunternehmen ist Secure Development ein Kernbaustein. [A.8.25]', 'Sichere Entwicklungsrichtlinie und Review-Standards etablieren.', 'CRITICAL', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('SDLC_TEST', 'SDLC', 'Werden Sicherheitstests (SAST, DAST, Pentests) regelmaessig durchgefuehrt?', 'Tests decken Schwachstellen vor dem Produktivbetrieb auf. [A.8.29]', 'Sicherheitstests in CI/CD-Pipeline integrieren.', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('SDLC_CHANGE', 'SDLC', 'Gibt es einen formalisierten Change-Management-Prozess?', 'Unkontrollierte Aenderungen sind ein haeufiger Angriffsvektor. [A.8.32]', 'Change-Management-Prozess mit Freigaben einfuehren.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, False),

            # CYBER (3 Fragen) – Annex A 8.7-8.12, 8.19
            ('CYBER_PATCH', 'CYBER', 'Gibt es ein geregeltes Patch- und Schwachstellenmanagement?', 'Cyberhygiene reduziert Basisrisiken signifikant. [A.8.8]', 'Patch- und Schwachstellenmanagement mit Fristen definieren.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('CYBER_HARDENING', 'CYBER', 'Werden Systeme nach Hardening-Standards konfiguriert?', 'Minimalkonfiguration reduziert die Angriffsflaeche. [A.8.9]', 'Hardening-Baselines fuer Server und Endgeraete definieren.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('CYBER_MALWARE', 'CYBER', 'Ist ein Schutz gegen Schadsoftware auf allen relevanten Systemen aktiv?', 'Malware-Schutz ist eine grundlegende Abwehrmassnahme. [A.8.7]', 'Endpoint-Protection auf allen Endgeraeten und Servern sicherstellen.', 'HIGH', 'SMALL', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),

            # CRYPTO (3 Fragen) – Annex A 8.24
            ('CRYPTO_POLICY', 'CRYPTO', 'Sind Verschluesselungsanforderungen und Schluesselverantwortlichkeiten definiert?', 'Kryptografie schuetzt sensible Daten und Schnittstellen. [A.8.24]', 'Kryptografie-Policy und Schluesselmanagement definieren.', 'MEDIUM', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, True),
            ('CRYPTO_TRANSIT', 'CRYPTO', 'Werden Daten bei Uebertragung verschluesselt (TLS, VPN)?', 'Unverschluesselte Uebertragung ermoeglicht Abhoeren. [A.8.24]', 'TLS/VPN fuer alle internen und externen Verbindungen sicherstellen.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('CRYPTO_REST', 'CRYPTO', 'Werden sensible Daten im Ruhezustand verschluesselt?', 'Verschluesselung at rest schuetzt bei Datentraegerverlust. [A.8.24]', 'Verschluesselung fuer Datenbanken und Backups pruefen und einrichten.', 'MEDIUM', 'MEDIUM', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, False),

            # PHYS (3 Fragen) – Annex A 7.1-7.4
            ('PHYS_ACCESS', 'PHYS', 'Gibt es physische Zugangskontrollen fuer Serverraeume und relevante Standorte?', 'Standortschutz ist Teil eines ganzheitlichen ISMS. [A.7.2]', 'Physische Zugangskontrollen dokumentieren.', 'MEDIUM', 'SMALL', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('PHYS_VISITOR', 'PHYS', 'Gibt es ein Besuchermanagement fuer sicherheitsrelevante Bereiche?', 'Unkontrollierter Zutritt Dritter gefaehrdet physische Sicherheit. [A.7.2]', 'Besuchermanagement-Prozess einfuehren.', 'LOW', 'SMALL', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, False),
            ('PHYS_ENV', 'PHYS', 'Sind Umgebungskontrollen (Klima, Brand, Wasser) fuer Serverraeume vorhanden?', 'Umgebungsereignisse koennen Verfuegbarkeit gefaehrden. [A.7.5]', 'Umgebungskontrollen pruefen und dokumentieren.', 'MEDIUM', 'MEDIUM', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, False),

            # DETECT (4 Fragen) – Annex A 8.15-8.16
            ('DETECT_LOGGING', 'DETECT', 'Existieren zentrales Logging und sicherheitsrelevante Alarmierungen?', 'Ohne Erkennung bleiben Sicherheitsvorfaelle lange unentdeckt. [A.8.15]', 'Logging, Monitoring und Alarmierungswege aufbauen.', 'CRITICAL', 'LARGE', 'TECHNICAL', 'Phase 4 – Quick Wins', True, True),
            ('DETECT_SIEM', 'DETECT', 'Werden Logs korreliert und automatisiert ausgewertet (SIEM o.ae.)?', 'Korrelation erkennt komplexe Angriffsmuster. [A.8.16]', 'SIEM oder vergleichbare Log-Korrelation einrichten.', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('DETECT_RETENTION', 'DETECT', 'Werden Logs ausreichend lange aufbewahrt?', 'Aufbewahrungsdauer muss regulatorische und forensische Anforderungen erfuellen.', 'Log-Retention-Policy definieren (min. 90 Tage).', 'MEDIUM', 'SMALL', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, True),
            ('DETECT_NETWORK', 'DETECT', 'Gibt es Netzwerk-Segmentierung und Monitoring kritischer Zonenuebergaenge?', 'Segmentierung begrenzt laterale Ausbreitung von Angreifern.', 'Netzwerk-Segmentierungskonzept umsetzen.', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, True),

            # INC (4 Fragen) – Annex A 5.24-5.28
            ('INC_RESPONSE', 'INC', 'Gibt es einen dokumentierten Incident-Management-Prozess mit Eskalationswegen?', 'Reaktionsfaehigkeit ist fuer NIS2 und Audit-Readiness zentral. [A.5.24]', 'Incident-Response-Prozess inklusive Meldewegen definieren.', 'CRITICAL', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 4 – Quick Wins', True, True),
            ('INC_NOTIFY', 'INC', 'Sind Meldewege an Behoerden und Betroffene definiert (NIS2 Art. 23)?', 'NIS2 fordert 24h-Fruehwarnung und 72h-Meldung bei erheblichen Vorfaellen.', 'Meldeprozess an BSI/CSIRT definieren und testen.', 'CRITICAL', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 4 – Quick Wins', False, True),
            ('INC_LESSONS', 'INC', 'Werden nach Vorfaellen Lessons Learned durchgefuehrt?', 'Kontinuierliche Verbesserung erfordert systematische Nachbereitung. [A.5.27]', 'Post-Incident-Review-Prozess etablieren.', 'MEDIUM', 'SMALL', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('INC_DRILL', 'INC', 'Werden Incident-Response-Uebungen regelmaessig durchgefuehrt?', 'Uebungen decken Luecken im Prozess auf bevor ein echter Vorfall eintritt.', 'Jaehrliche IR-Uebung oder Tabletop-Simulation planen.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 6 – Audit Readiness', True, True),

            # BCM (4 Fragen) – Annex A 5.29-5.30, 8.13-8.14
            ('BCM_BACKUP', 'BCM', 'Sind Backup, Restore und Wiederanlauf getestet und nachweisbar?', 'Resilienz und Wiederanlauf sind zentrale Kontrollziele. [A.8.13]', 'Backup-/Restore-Konzept testen und Evidenzen sichern.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, True),
            ('BCM_BIA', 'BCM', 'Wurde eine Business-Impact-Analyse durchgefuehrt?', 'BIA identifiziert kritische Prozesse und maximale Ausfallzeiten. [A.5.29]', 'BIA fuer Kernprozesse durchfuehren und dokumentieren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', True, True),
            ('BCM_PLAN', 'BCM', 'Existieren Wiederanlaufplaene fuer kritische Prozesse?', 'Ohne Plaene dauert die Wiederherstellung unverhältnismäßig lange. [A.5.30]', 'Wiederanlaufplaene mit RTO/RPO erstellen.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', True, True),
            ('BCM_TEST', 'BCM', 'Werden BCM-Plaene regelmaessig getestet?', 'Ungetestete Plaene sind im Ernstfall nicht verlaesslich.', 'Jaehrlichen BCM-Test mit Dokumentation durchfuehren.', 'MEDIUM', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 6 – Audit Readiness', True, True),

            # AWARE (3 Fragen) – Annex A 6.3
            ('AWARE_TRAINING', 'AWARE', 'Gibt es rollenbezogene Awareness- und Security-Schulungen?', 'Awareness staerkt die Wirksamkeit organisatorischer Controls. [A.6.3]', 'Awareness-Programm mit Nachweisen etablieren.', 'MEDIUM', 'SMALL', 'ORGANIZATIONAL', 'Phase 4 – Quick Wins', True, True),
            ('AWARE_PHISHING', 'AWARE', 'Werden Phishing-Simulationen oder Social-Engineering-Tests durchgefuehrt?', 'Realistische Tests messen die tatsaechliche Widerstandsfaehigkeit.', 'Phishing-Simulationen jaehrlich durchfuehren.', 'MEDIUM', 'MEDIUM', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', True, False),
            ('AWARE_ONBOARDING', 'AWARE', 'Ist Informationssicherheit Teil des Onboarding-Prozesses?', 'Fruehe Sensibilisierung reduziert Risiken durch neue Mitarbeitende. [A.6.3]', 'IS-Schulung in Onboarding-Prozess integrieren.', 'MEDIUM', 'SMALL', 'ORGANIZATIONAL', 'Phase 4 – Quick Wins', True, False),
            # DOC (3 Fragen) – Annex A 5.1, 5.37
            ('DOC_REVIEWS', 'DOC', 'Werden Policies und Prozesse regelmaessig reviewed und versioniert?', 'Review-Zyklen sind fuer Reifegrad und Auditfaehigkeit relevant. [A.5.37]', 'Review-Zyklen und Versionierung verbindlich einfuehren.', 'HIGH', 'SMALL', 'DOCUMENTARY', 'Phase 6 – Audit Readiness', True, True),
            ('DOC_APPROVAL', 'DOC', 'Gibt es einen definierten Freigabeprozess fuer Richtlinien?', 'Freigegebene Dokumente haben bindende Wirkung. [A.5.1]', 'Freigabeworkflow fuer Richtlinien etablieren.', 'MEDIUM', 'SMALL', 'DOCUMENTARY', 'Phase 1 – Governance', True, False),
            ('DOC_COMMUNICATION', 'DOC', 'Werden freigegebene Richtlinien aktiv an Betroffene kommuniziert?', 'Policies ohne Kommunikation sind wirkungslos. [A.5.1]', 'Kommunikationsplan fuer Policies erstellen.', 'MEDIUM', 'SMALL', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, False),

            # PSM / Product Security (4 Fragen)
            ('PSM_SECURE_BY_DESIGN', 'PSM', 'Sind Product-Security-Anforderungen fuer Produkte mit digitalen Elementen definiert?', 'CRA und Product Security verlangen Secure by Design und Lifecycle Governance.', 'Product-Security-Anforderungen und Secure-by-Design-Leitplanken definieren.', 'CRITICAL', 'MEDIUM', 'DOCUMENTARY', 'Phase 1 – Governance', True, False, True, False, False, False),
            ('PSM_RELEASE_GATES', 'PSM', 'Gibt es Security Release Gates und Freigabekriterien fuer Produkt-Releases?', 'Produktfreigaben brauchen Security-Sign-off, Test- und Risikokriterien.', 'Release-Gates und Security Sign-off fuer Produkt-Releases etablieren.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', True, False, True, False, False, False),
            ('PSM_SBOM', 'PSM', 'Werden Komponenten, Bibliotheken und SBOM-bezogene Informationen gepflegt?', 'CRA-/Product-Security-Readiness braucht Transparenz ueber Komponenten und Abhaengigkeiten.', 'SBOM- und Komponenten-Governance aufbauen.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 2 – Transparenz', True, False, True, False, False, False),
            ('PSM_SUPPORT', 'PSM', 'Sind Support-, Patch- und End-of-Life-Verantwortungen fuer Produkte geregelt?', 'Product Security umfasst auch Wartung, Support und Lifecycle-Verantwortung.', 'Support-/Patch-/EOL-Verantwortungen fuer Produkte definieren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', False, False, True, False, False, False),

            # PSIRT (3 Fragen)
            ('PSIRT_PROCESS', 'PSIRT', 'Gibt es einen dokumentierten PSIRT-/Vulnerability-Handling-Prozess?', 'Schwachstellenmanagement fuer Produkte braucht Triage, Advisory- und Patch-Prozesse.', 'PSIRT- und Vulnerability-Handling-Prozess einrichten.', 'CRITICAL', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 4 – Quick Wins', False, False, True, False, False, False),
            ('PSIRT_DISCLOSURE', 'PSIRT', 'Sind Disclosure-, Advisory- und Kundenkommunikationswege definiert?', 'Produkt-Schwachstellen erfordern koordinierte Offenlegung und Kundennotifikation.', 'Coordinated Disclosure und Advisory-Workflow definieren.', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', False, False, True, False, False, False),
            ('PSIRT_TRACKING', 'PSIRT', 'Werden Produkt-Schwachstellen inklusive Fix-/Mitigation-Status nachverfolgt?', 'Product Security braucht nachvollziehbares Tracking von offenen Findings bis zur Behebung.', 'Vulnerability-Tracking und Remediation-SLA einfuehren.', 'HIGH', 'MEDIUM', 'TECHNICAL', 'Phase 4 – Quick Wins', False, False, True, False, False, False),

            # AI Governance (3 Fragen)
            ('AI_INVENTORY', 'AIGOV', 'Gibt es ein Inventar fuer AI-Systeme, Modelle und Provider?', 'AI-Governance beginnt mit Transparenz ueber Systeme, Modelle und externe Provider.', 'AI-System- und Provider-Register aufbauen.', 'HIGH', 'SMALL', 'DOCUMENTARY', 'Phase 2 – Transparenz', False, False, False, True, False, False),
            ('AI_RISK_CLASS', 'AIGOV', 'Werden AI-Use-Cases risikobasiert klassifiziert und dokumentiert?', 'AI Act Readiness erfordert je nach Scope eine nachvollziehbare Klassifizierung.', 'AI-Risikoklassifizierung und Governance-Leitfaden definieren.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 1 – Governance', False, False, False, True, False, False),
            ('AI_MONITORING', 'AIGOV', 'Sind Logging, Monitoring und Human Oversight fuer relevante AI-Funktionen geregelt?', 'Fuer relevante AI-Funktionen sind Oversight und Monitoring wesentliche Governance-Bausteine.', 'AI-Monitoring und Human-Oversight-Prozess aufbauen.', 'HIGH', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', False, False, False, True, False, False),

            # OT / IEC 62443 (3 Fragen)
            ('OT_ZONES', 'OTSEC', 'Sind OT-/IACS-Zonen, Conduits und Segmentierungsprinzipien definiert?', 'IEC 62443-orientierte Security braucht Segmentierung und Systemgrenzen.', 'Zonen-/Conduit-Modell und Segmentierung dokumentieren.', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', False, False, False, False, True, False),
            ('OT_COMPONENTS', 'OTSEC', 'Werden industrielle Komponenten und Integrationsverantwortungen sicherheitsbezogen erfasst?', 'Industrial Security benoetigt Komponenten-, Supplier- und Integrator-Transparenz.', 'OT-Komponenten- und Integrator-Register pflegen.', 'MEDIUM', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', False, False, False, False, True, False),
            ('OT_LEVELS', 'OTSEC', 'Sind Security Levels bzw. industrielle Schutzanforderungen definiert?', 'IEC 62443 arbeitet mit Security Levels und systematischer Schutzbedarfsermittlung.', 'Security Levels und industrielle Schutzanforderungen definieren.', 'MEDIUM', 'MEDIUM', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', False, False, False, False, True, False),

            # Automotive / ISO-SAE 21434 (3 Fragen)
            ('AUTO_TARA', 'AUTO', 'Wird eine Threat Analysis and Risk Assessment (TARA) fuer relevante Systeme durchgefuehrt?', 'ISO/SAE 21434 verlangt Cybersecurity Engineering und TARA ueber den Lebenszyklus.', 'TARA-Prozess und Templates etablieren.', 'HIGH', 'LARGE', 'ORGANIZATIONAL', 'Phase 5 – Strukturmassnahmen', False, False, False, False, False, True),
            ('AUTO_TRACE', 'AUTO', 'Sind Cybersecurity-Ziele und Nachweise ueber Anforderungen, Tests und Releases rueckverfolgbar?', 'Automotive Cybersecurity braucht Traceability ueber den Produktlebenszyklus.', 'Traceability von Cybersecurity-Zielen zu Anforderungen und Tests aufbauen.', 'HIGH', 'LARGE', 'DOCUMENTARY', 'Phase 5 – Strukturmassnahmen', False, False, False, False, False, True),
            ('AUTO_FIELD', 'AUTO', 'Gibt es Field-Monitoring, Incident-Handling und Update-Faehigkeit fuer ausgelieferte Systeme?', 'Lifecycle Cybersecurity im Fahrzeugkontext umfasst Betrieb, Monitoring und Updates.', 'Field-Monitoring- und Updateability-Konzept etablieren.', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', False, False, False, False, False, True),
        ]


        for idx, item in enumerate(maturity_questions, start=1):
            if len(item) == 11:
                code, domain_code, text, why, rec_title, priority, effort, measure_type, target_phase, iso, nis2 = item
                cra = ai_act = iec62443 = iso_sae_21434 = False
            elif len(item) == 15:
                code, domain_code, text, why, rec_title, priority, effort, measure_type, target_phase, iso, nis2, cra, ai_act, iec62443, iso_sae_21434 = item
            else:
                raise ValueError(f'Unexpected question tuple length for {item!r}')
            question, _ = AssessmentQuestion.objects.update_or_create(
                code=code,
                defaults={
                    'domain': domain_map[domain_code],
                    'text': text,
                    'help_text': text,
                    'why_it_matters': why,
                    'question_kind': AssessmentQuestion.Kind.MATURITY,
                    'wizard_step': AssessmentQuestion.Step.MATURITY,
                    'weight': domain_map[domain_code].weight,
                    'is_required': True,
                    'applies_to_iso27001': iso,
                    'applies_to_nis2': nis2,
                    'applies_to_cra': cra,
                    'applies_to_ai_act': ai_act,
                    'applies_to_iec62443': iec62443,
                    'applies_to_iso_sae_21434': iso_sae_21434,
                    'applies_to_product_security': any([cra, ai_act, iec62443, iso_sae_21434]),
                    'sort_order': idx * 10,
                },
            )
            for opt_idx, (slug, label, score, description) in enumerate(MATURITY_OPTIONS, start=1):
                AnswerOption.objects.update_or_create(
                    question=question, slug=slug,
                    defaults={'label': label, 'score': score, 'description': description, 'sort_order': opt_idx * 10, 'is_na': slug == 'na'},
                )
            RecommendationRule.objects.update_or_create(
                question=question, max_score_threshold=2, title=rec_title,
                defaults={
                    'description': f'Diese Massnahme wird empfohlen, weil die Frage "{text}" derzeit nicht ausreichend beantwortet wurde.',
                    'priority': priority, 'effort': effort, 'measure_type': measure_type,
                    'owner_role': 'ISMS Manager', 'target_phase': target_phase, 'sort_order': 10,
                },
            )

        total_q = AssessmentQuestion.objects.filter(question_kind=AssessmentQuestion.Kind.MATURITY).count()
        self.stdout.write(self.style.SUCCESS(f'Catalog seeded: {total_q} Maturity-Fragen ueber {len(domains)} Domaenen.'))
