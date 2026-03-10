"""Wizard-Service V19 – Findings F01, F02, F03, F05, F08, F16, F17 umgesetzt."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List, Optional

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.catalog.models import AssessmentDomain, AssessmentQuestion
from apps.core.models import AuditLog
from apps.organizations.models import BusinessUnit, Supplier, Tenant
from apps.organizations.sector_catalog import get_sector_definition
from apps.organizations.country_catalog import EU_EEA_CODES, get_country_labels
from apps.processes.models import Process
from apps.reports.models import ReportSnapshot
from apps.evidence.services import EvidenceNeedService
from apps.roadmap.models import RoadmapPlan, RoadmapPhase, RoadmapTask, RoadmapTaskDependency
from apps.product_security.services import ProductSecurityService
from .models import AssessmentSession, DomainScore, GeneratedGap, GeneratedMeasure, SessionAnswer


@dataclass
class ApplicabilityResult:
    label: str
    nis2_category: str          # F01: 'besonders_wichtig', 'wichtig', 'nicht_betroffen'
    reasoning: str
    score: int
    kritis_indication: str      # F03: Klartext-Indikation


# ──────────────────────────────────────────────────────────────────────
# F01: NIS2-Klassifikation – 'besonders wichtig' vs 'wichtig' sauber trennen
# F02: Groessenschwellen nur aus strukturierten Feldern, keine Doppelzaehlung
# ──────────────────────────────────────────────────────────────────────

def _classify_company_size(tenant: Tenant) -> dict:
    """F02: Einmalige, zentrale Groessenklassifizierung aus den strukturierten Feldern."""
    employees = tenant.employee_count or 0
    revenue = float(tenant.annual_revenue_million or 0)
    balance = float(tenant.balance_sheet_million or 0)

    is_large = employees >= 250 or revenue >= 50 or balance >= 43
    is_medium = (not is_large) and (employees >= 50 or revenue >= 10 or balance >= 10)

    return {
        'is_large': is_large,
        'is_medium': is_medium,
        'is_small': not is_large and not is_medium,
        'size_label': 'Grossunternehmen' if is_large else 'Mittleres Unternehmen' if is_medium else 'Kleinunternehmen',
        'employees': employees,
        'revenue': revenue,
        'balance': balance,
    }


def _determine_nis2_category(sector, size_info: dict, answer_score: int, country_context: dict) -> tuple:
    """F01: Bestimmt die NIS2-Einrichtungskategorie nach Art. 3 NIS2.

    Besonders wichtige Einrichtung (Art. 3 Abs. 1):
      - Anhang-I-Sektor UND Grossunternehmen
      - ODER qualifizierte Vertrauensdiensteanbieter, TLD-Registrierungen, DNS etc.

    Wichtige Einrichtung (Art. 3 Abs. 2):
      - Anhang-I oder Anhang-II-Sektor UND mindestens mittleres Unternehmen
      - Und nicht bereits besonders wichtig
    """
    is_annex_i = sector.nis2_annex == 'I'
    is_annex_ii = sector.nis2_annex == 'II'
    is_regulated_sector = is_annex_i or is_annex_ii

    if is_annex_i and size_info['is_large']:
        return (
            'Voraussichtlich besonders wichtige Einrichtung (Art. 3 Abs. 1 NIS2)',
            'besonders_wichtig',
        )
    if is_annex_i and size_info['is_medium']:
        return (
            'Voraussichtlich wichtige Einrichtung (Art. 3 Abs. 2 NIS2)',
            'wichtig',
        )
    if is_annex_ii and (size_info['is_large'] or size_info['is_medium']):
        return (
            'Voraussichtlich wichtige Einrichtung (Art. 3 Abs. 2 NIS2)',
            'wichtig',
        )
    # Indirekte Relevanz ueber Lieferkette / hohen Answer-Score
    if is_regulated_sector and answer_score >= 12:
        return (
            'Moeglicherweise relevant / erhoehte regulatorische Naehe',
            'moeglich',
        )
    if answer_score >= 10 or (is_regulated_sector and size_info['is_small']):
        return (
            'Moeglicherweise relevant – Einzelfallpruefung empfohlen',
            'moeglich',
        )
    return (
        'Aktuell nicht direkt betroffen – ISO-27001-first empfohlen',
        'nicht_betroffen',
    )


def _determine_kritis_indication(sector, size_info: dict) -> str:
    """F03: KRITIS-Indikation mit Hinweis auf sektorspezifische Schwellenwerte."""
    if not sector.kritis_related:
        return 'Sektor ist nicht KRITIS-nah – keine KRITIS-Indikation.'
    note = sector.kritis_note or 'Sektorspezifische Schwellenwerte der BSI-KritisV pruefen.'
    if size_info['is_large']:
        return f'Erhoehte KRITIS-Indikation (Grossunternehmen in KRITIS-nahem Sektor). HINWEIS: Dies ist KEINE KRITIS-Einstufung. {note}'
    if size_info['is_medium']:
        return f'Moderate KRITIS-Indikation (mittleres Unternehmen in KRITIS-nahem Sektor). {note}'
    return f'Geringere KRITIS-Indikation (Kleinunternehmen), aber sektorale Pruefung empfohlen. {note}'


class WizardService:
    PHASE_SEQUENCE = [
        ('Phase 1 – Governance', 'Scope, Verantwortlichkeiten und Management-Commitment festlegen.', 2),
        ('Phase 2 – Transparenz', 'Geschaeftsbereiche, Prozesse, Assets und Lieferanten erfassen.', 3),
        ('Phase 3 – Gap-Analyse', 'Domaenen bewerten, Gaps priorisieren und Quick Wins identifizieren.', 2),
        ('Phase 4 – Quick Wins', 'MFA, Logging, Incident-Meldewege und Awareness kurzfristig anheben.', 4),
        ('Phase 5 – Strukturmassnahmen', 'Lieferkette, SDLC, Backup/BCM und Reviews nachhaltig staerken.', 6),
        ('Phase 6 – Audit Readiness', 'Management Review, Nachweise und Zertifizierungsfaehigkeit vorbereiten.', 2),
    ]

    @staticmethod
    def get_default_tenant(user):
        """F09: Kein .first()-Fallback mehr. Nur den Tenant des Users zurueckgeben."""
        if getattr(user, 'tenant', None):
            return user.tenant
        return None

    @staticmethod
    def get_sector_context(tenant: Tenant | None):
        sector = get_sector_definition(getattr(tenant, 'sector', None))
        return {
            'code': sector.code,
            'label': sector.label,
            'nis2_group': sector.nis2_group,
            'nis2_annex': sector.nis2_annex,
            'indicative_classification': sector.indicative_classification,
            'reasoning': sector.reasoning,
            'downstream_impact': sector.downstream_impact,
            'roadmap_focus': sector.roadmap_focus,
            'key_domains': sector.key_domains,
            'special_regime': sector.special_regime,
            'kritis_related': sector.kritis_related,
            'kritis_note': sector.kritis_note,
            'score_bonus': sector.score_bonus,
        }

    @staticmethod
    def get_country_context(tenant: Tenant | None):
        if not tenant:
            return {
                'selected_codes': [], 'selected_labels': [], 'display': '-',
                'count': 0, 'is_multi_country': False, 'includes_germany': False,
                'has_non_eu_eea': False, 'geo_impact': 'Noch keine Laender ausgewaehlt.',
            }
        selected_codes = tenant.operation_countries or ([tenant.country] if tenant.country else [])
        selected_labels = get_country_labels(selected_codes)
        includes_germany = 'DE' in selected_codes
        has_non_eu_eea = any(code not in EU_EEA_CODES for code in selected_codes)
        is_multi_country = len(selected_codes) > 1

        impact_parts = []
        if includes_germany:
            impact_parts.append('Deutschland bleibt Referenzmarkt fuer die regulatorische Einordnung und die Basis-Roadmap.')
        if is_multi_country:
            impact_parts.append('Mehrere Laender erhoehen den Bedarf an grenzueberschreitender Governance, Incident-Koordination und harmonisierten Policies.')
        if has_non_eu_eea:
            impact_parts.append('Nicht-EU-/EWR-Laender erfordern zusaetzliche Pruefung von Drittlandbezuegen, Lieferkette und Datenfluessen.')
        if not impact_parts:
            impact_parts.append('Einzelstaatlicher Fokus erlaubt einen kompakteren Scope und eine schlankere Umsetzungsroadmap.')

        return {
            'selected_codes': selected_codes, 'selected_labels': selected_labels,
            'display': ', '.join(selected_labels) if selected_labels else '-',
            'count': len(selected_codes), 'is_multi_country': is_multi_country,
            'includes_germany': includes_germany, 'has_non_eu_eea': has_non_eu_eea,
            'geo_impact': ' '.join(impact_parts),
        }

    @staticmethod
    def get_mode_context(session_or_type):
        assessment_type = session_or_type.assessment_type if hasattr(session_or_type, 'assessment_type') else session_or_type
        if assessment_type == AssessmentSession.Type.APPLICABILITY:
            return {
                'code': AssessmentSession.Type.APPLICABILITY,
                'title': 'NIS2-/KRITIS-Relevanz pruefen',
                'summary': 'Fokussiert auf Sektor, Schwellenwerte, Laenderkontext und eine unverbindliche Betroffenheitsindikation. Keine vollstaendige Gap-Analyse.',
                'steps': ['Unternehmensprofil', 'Betroffenheitspruefung', 'Ergebnis'],
            }
        if assessment_type == AssessmentSession.Type.ISO_READINESS:
            return {
                'code': AssessmentSession.Type.ISO_READINESS,
                'title': 'ISO-27001-Readiness bewerten',
                'summary': 'Fokussiert auf Scope, Reifegrad und ISO-orientierte Massnahmen. Keine NIS2-/KRITIS-Einstufung als Ergebnis.',
                'steps': ['Unternehmensprofil', 'Scope & Struktur', 'Reifegradanalyse', 'Ergebnis'],
            }
        return {
            'code': AssessmentSession.Type.FULL,
            'title': 'Vollstaendige ISMS-/NIS2-Gap-Analyse',
            'summary': 'Kombiniert Betroffenheitspruefung, Scope, Reifegradanalyse, Massnahmen und Roadmap.',
            'steps': ['Unternehmensprofil', 'Betroffenheitspruefung', 'Scope & Struktur', 'Reifegradanalyse', 'Ergebnis'],
        }

    @staticmethod
    def next_step_after_profile(session: AssessmentSession):
        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            return AssessmentSession.Step.APPLICABILITY
        return AssessmentSession.Step.SCOPE if session.assessment_type == AssessmentSession.Type.ISO_READINESS else AssessmentSession.Step.APPLICABILITY

    @staticmethod
    def update_progress(session: AssessmentSession):
        mapping = {
            AssessmentSession.Step.PROFILE: 10,
            AssessmentSession.Step.APPLICABILITY: 30,
            AssessmentSession.Step.SCOPE: 50,
            AssessmentSession.Step.MATURITY: 75,
            AssessmentSession.Step.RESULTS: 100,
        }
        session.progress_percent = mapping.get(session.current_step, 0)
        session.save(update_fields=['progress_percent', 'updated_at'])

    @staticmethod
    def save_answers(session: AssessmentSession, answers: Dict[str, str], comments: Dict[str, str] | None = None):
        comments = comments or {}
        questions = AssessmentQuestion.objects.filter(code__in=answers.keys()).prefetch_related('options')
        for question in questions:
            option = question.options.filter(id=answers[question.code]).first()
            SessionAnswer.objects.update_or_create(
                session=session,
                question=question,
                defaults={
                    'selected_option': option,
                    'score': option.score if option else 0,
                    'comment': comments.get(question.code, ''),
                    # F08: N/A-Flag direkt speichern
                    'is_na': option.is_na if option else False,
                },
            )

    @staticmethod
    def evaluate_applicability(session: AssessmentSession) -> ApplicabilityResult:
        """F01+F02: Saubere NIS2-Klassifikation ohne Doppelzaehlung."""
        answers = session.answers.select_related('question', 'selected_option').filter(
            question__question_kind=AssessmentQuestion.Kind.APPLICABILITY
        )
        # F02: Nur Answer-Scores verwenden, keine separaten size/finance-Boni mehr
        answer_score = sum(answer.score for answer in answers)
        sector = get_sector_definition(session.tenant.sector)
        country_context = WizardService.get_country_context(session.tenant)
        size_info = _classify_company_size(session.tenant)

        # F01: Saubere Klassifikation
        label, nis2_category = _determine_nis2_category(sector, size_info, answer_score, country_context)

        # F03: KRITIS-Indikation
        kritis_indication = _determine_kritis_indication(sector, size_info)

        total_score = answer_score + sector.score_bonus

        reasoning_parts = [
            f'Ausgewaehlter Sektor: {sector.label} ({sector.nis2_group}).',
            f'Unternehmensgroesse: {size_info["size_label"]} ({size_info["employees"]} MA, {size_info["revenue"]} Mio. EUR Umsatz, {size_info["balance"]} Mio. EUR Bilanzsumme).',
            sector.reasoning,
            f'Die Auswahl beeinflusst den weiteren Prozess wie folgt: {sector.downstream_impact}',
            f'Ausgewaehlte Laender/Prasenzen: {country_context["display"]}. {country_context["geo_impact"]}',
        ]
        if sector.special_regime:
            reasoning_parts.append(f'Zusaetzliche sektorale Pruefung: {sector.special_regime}.')
        if kritis_indication:
            reasoning_parts.append(f'KRITIS-Indikation: {kritis_indication}')
        if session.tenant.critical_services:
            reasoning_parts.append('Kritische Dienstleistungen wurden angegeben und erhoehen die fachliche Relevanz der Folgeanalyse.')
        if getattr(session.tenant, 'supply_chain_role', ''):
            reasoning_parts.append('Die Lieferkettenrolle wird in der Priorisierung von Massnahmen mitberuecksichtigt.')
        reasoning_parts.append(ProductSecurityService.build_summary(session.tenant, ProductSecurityService.get_regime_matrix(session.tenant)))

        session.tenant.nis2_relevant = nis2_category in ('besonders_wichtig', 'wichtig', 'moeglich')
        session.tenant.kritis_relevant = sector.kritis_related and (size_info['is_large'] or size_info['is_medium'])
        session.tenant.save(update_fields=['nis2_relevant', 'kritis_relevant', 'updated_at'])
        session.applicability_result = label
        session.applicability_reasoning = ' '.join(reasoning_parts)
        session.save(update_fields=['applicability_result', 'applicability_reasoning', 'updated_at'])
        return ApplicabilityResult(
            label=label,
            nis2_category=nis2_category,
            reasoning=session.applicability_reasoning,
            score=total_score,
            kritis_indication=kritis_indication,
        )

    @staticmethod
    @transaction.atomic
    def generate_results(session: AssessmentSession):
        session.domain_scores.all().delete()
        session.generated_gaps.all().delete()
        session.generated_measures.all().delete()
        session.roadmap_plans.all().delete()
        session.report_snapshots.all().delete()

        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            return WizardService._generate_applicability_only_results(session)

        domain_scores = []
        answers = {a.question_id: a for a in session.answers.select_related('question', 'selected_option', 'question__domain')}
        domains = AssessmentDomain.objects.prefetch_related('questions__recommendation_rules').all()

        for domain in domains:
            questions = domain.questions.filter(question_kind=AssessmentQuestion.Kind.MATURITY)
            if session.assessment_type == AssessmentSession.Type.ISO_READINESS:
                questions = questions.filter(applies_to_iso27001=True)
            if not questions.exists():
                continue

            # F08: N/A-Antworten aus Berechnung ausschliessen
            answered_questions = []
            for question in questions:
                answer = answers.get(question.id)
                is_na = getattr(answer, 'is_na', False) if answer else False
                if answer and answer.selected_option and answer.selected_option.is_na:
                    is_na = True
                if not is_na:
                    answered_questions.append((question, answer))

            if not answered_questions:
                continue

            max_score = len(answered_questions) * 5
            raw_score = 0
            for question, answer in answered_questions:
                score = answer.score if answer else 0
                raw_score += score
                if answer is None or score <= 2:
                    severity = 'CRITICAL' if answer is None or score == 0 else 'HIGH' if score == 1 else 'MEDIUM'
                    session.generated_gaps.create(
                        domain=domain,
                        question=question,
                        severity=severity,
                        title=f'Gap in {domain.name}: {question.text}',
                        description=question.why_it_matters or question.help_text,
                    )
                    for rule in question.recommendation_rules.filter(max_score_threshold__gte=score).order_by('sort_order')[:1]:
                        session.generated_measures.create(
                            domain=domain,
                            question=question,
                            title=rule.title,
                            description=rule.description,
                            priority=rule.priority,
                            effort=rule.effort,
                            measure_type=rule.measure_type,
                            target_phase=rule.target_phase,
                            owner_role=rule.owner_role,
                            reason=f'Abgeleitet aus Antwortscore {score} fuer: {question.text}',
                        )
            percent = int((raw_score / max_score) * 100) if max_score else 0
            if percent <= 20:
                maturity, gap = 'Kritisch', 'CRITICAL'
            elif percent <= 40:
                maturity, gap = 'Sehr niedriger Reifegrad', 'HIGH'
            elif percent <= 60:
                maturity, gap = 'Grundlagen vorhanden', 'MEDIUM'
            elif percent <= 80:
                maturity, gap = 'Brauchbare Readiness', 'LOW'
            else:
                maturity, gap = 'Fortgeschritten / auditnah', 'LOW'
            domain_scores.append(
                DomainScore.objects.create(
                    session=session, domain=domain,
                    score_raw=raw_score, score_percent=percent,
                    maturity_level=maturity, gap_level=gap,
                )
            )

        if session.assessment_type == AssessmentSession.Type.FULL:
            WizardService.evaluate_applicability(session)
            WizardService._generate_sector_specific_measures(session)
            WizardService._generate_country_specific_measures(session)
        else:
            session.applicability_result = 'ISO-27001-Fokusmodus – keine NIS2-/KRITIS-Einstufung durchgefuehrt'
            session.applicability_reasoning = 'Dieser Modus bewertet die organisatorische und technische Readiness gegen einen ISO-27001-orientierten Fragenkatalog. Eine regulatorische NIS2-/KRITIS-Einordnung ist nicht Teil dieses Assessments.'
            session.save(update_fields=['applicability_result', 'applicability_reasoning', 'updated_at'])
            WizardService._generate_iso_context_measures(session)
            WizardService._generate_country_specific_measures(session)

        ProductSecurityService.generate_measures(session)
        WizardService._generate_roadmap(session)
        session.executive_summary = WizardService._build_executive_summary(session, domain_scores)
        WizardService._generate_report(session, domain_scores)
        EvidenceNeedService.sync_for_session(session)
        ProductSecurityService.sync_snapshot_for_tenant(session.tenant, session)
        session.status = AssessmentSession.Status.COMPLETED
        session.current_step = AssessmentSession.Step.RESULTS
        session.progress_percent = 100
        session.completed_at = timezone.now()
        session.save()
        return domain_scores

    @staticmethod
    def _generate_applicability_only_results(session: AssessmentSession):
        result = WizardService.evaluate_applicability(session)
        sector = get_sector_definition(session.tenant.sector)
        country_context = WizardService.get_country_context(session.tenant)

        session.generated_measures.get_or_create(
            title='Betroffenheitspruefung rechtlich und organisatorisch validieren',
            defaults={
                'description': 'Die automatisierte Vorpruefung ist unverbindlich. Pruefen Sie Schwellenwerte, Einrichtungsart, Konzernkontext und moegliche Ausnahmen mit Compliance-/Rechtsfunktion.',
                'priority': 'CRITICAL' if result.nis2_category in ('besonders_wichtig', 'wichtig') else 'HIGH',
                'effort': 'SMALL',
                'measure_type': 'DOCUMENTARY',
                'target_phase': 'Phase 1 – Governance',
                'owner_role': 'Compliance Manager',
                'reason': 'Aus dem Modus NIS2-/KRITIS-Relevanz pruefen abgeleitet.',
            },
        )
        if result.nis2_category in ('besonders_wichtig', 'wichtig'):
            session.generated_measures.get_or_create(
                title='NIS2-nahe Pflichten vorbereiten: Registrierung, Meldewege, Risikomanagement',
                defaults={
                    'description': 'Bereiten Sie Rollen, Meldewege, erste Risikoanalyse und Registrierungsinformationen fuer eine moegliche NIS2-Betroffenheit vor.',
                    'priority': 'HIGH',
                    'effort': 'MEDIUM',
                    'measure_type': 'ORGANIZATIONAL',
                    'target_phase': 'Phase 2 – Transparenz',
                    'owner_role': 'ISMS Manager',
                    'reason': f'Betroffenheitsindikation: {result.nis2_category}.',
                },
            )
        elif result.nis2_category == 'moeglich':
            session.generated_measures.get_or_create(
                title='Vertiefte NIS2-Einzelfallpruefung durchfuehren',
                defaults={
                    'description': 'Die Vorpruefung zeigt moegliche Relevanz. Eine vertiefte Pruefung mit juristischer Unterstuetzung wird empfohlen.',
                    'priority': 'HIGH',
                    'effort': 'SMALL',
                    'measure_type': 'DOCUMENTARY',
                    'target_phase': 'Phase 1 – Governance',
                    'owner_role': 'Compliance Manager',
                    'reason': 'Indikation: moeglicherweise relevant.',
                },
            )
        else:
            session.generated_measures.get_or_create(
                title='ISO-27001-Readiness als strukturierte Anschlussmassnahme starten',
                defaults={
                    'description': 'Auch ohne direkte NIS2-Betroffenheit ist ein ISO-27001-orientierter Aufbau sinnvoll.',
                    'priority': 'MEDIUM',
                    'effort': 'MEDIUM',
                    'measure_type': 'ORGANIZATIONAL',
                    'target_phase': 'Phase 2 – Transparenz',
                    'owner_role': 'ISMS Manager',
                    'reason': 'Keine direkte Betroffenheit erkannt; ISO-first empfohlen.',
                },
            )
        if country_context['is_multi_country']:
            WizardService._generate_country_specific_measures(session)
        ProductSecurityService.generate_measures(session)

        session.executive_summary = (
            f'Die Vorpruefung fuer {session.tenant.name} im Sektor {sector.label} ergibt: {result.label}. '
            f'NIS2-Kategorie: {result.nis2_category}. '
            f'{result.kritis_indication} '
            f'Laenderkontext: {country_context["display"]}. {country_context["geo_impact"]}'
        )
        WizardService._generate_roadmap(session)
        WizardService._generate_report(session, [])
        ProductSecurityService.sync_snapshot_for_tenant(session.tenant, session)
        session.status = AssessmentSession.Status.COMPLETED
        session.current_step = AssessmentSession.Step.RESULTS
        session.progress_percent = 100
        session.completed_at = timezone.now()
        session.save()
        return []

    @staticmethod
    def _generate_iso_context_measures(session: AssessmentSession):
        sector = get_sector_definition(session.tenant.sector)
        session.generated_measures.get_or_create(
            title=f'Sektoralen Schwerpunkt {sector.label} in der ISO-Roadmap priorisieren',
            defaults={
                'description': f'Der gewaehlte Sektor {sector.label} beeinflusst die Reihenfolge der Kontroll- und Massnahmenpakete. Priorisieren Sie insbesondere: {", ".join(sector.roadmap_focus[:3])}.',
                'priority': 'HIGH' if sector.score_bonus >= 4 else 'MEDIUM',
                'effort': 'SMALL',
                'measure_type': 'DOCUMENTARY',
                'target_phase': 'Phase 1 – Governance',
                'owner_role': 'ISMS Manager',
                'reason': 'Sektor wirkt in diesem Modus auf Schwerpunktsetzung, nicht auf regulatorische Einstufung.',
            },
        )

    @staticmethod
    def _generate_sector_specific_measures(session: AssessmentSession):
        sector = get_sector_definition(session.tenant.sector)
        sector_domain_map = {domain.code: domain for domain in AssessmentDomain.objects.filter(code__in=sector.key_domains)}

        common_title = f'Sektor-spezifische Pflichten und Schwellenwerte fuer {sector.label} fachlich verifizieren'
        session.generated_measures.get_or_create(
            title=common_title,
            defaults={
                'domain': sector_domain_map.get(sector.key_domains[0]) if sector.key_domains else None,
                'description': f'Pruefen, welche Einrichtungsarten, Schwellenwerte und Melde-/Registrierungspflichten fuer den gewaehlten Sektor {sector.label} einschlaegig sind.',
                'priority': 'CRITICAL' if sector.score_bonus >= 6 else 'HIGH' if sector.score_bonus >= 4 else 'MEDIUM',
                'effort': 'MEDIUM',
                'measure_type': 'DOCUMENTARY',
                'target_phase': 'Phase 1 – Governance',
                'owner_role': 'Compliance Manager',
                'reason': 'Automatisch aus der Sektorauswahl abgeleitet.',
            },
        )

        if sector.special_regime:
            session.generated_measures.get_or_create(
                title=f'{sector.special_regime} in der Zielarchitektur beruecksichtigen',
                defaults={
                    'domain': sector_domain_map.get('DOC') or sector_domain_map.get(sector.key_domains[0]) if sector.key_domains else None,
                    'description': f'Der gewaehlte Sektor weist auf eine moegliche sektorale Spezialregulierung hin: {sector.special_regime}.',
                    'priority': 'HIGH',
                    'effort': 'SMALL',
                    'measure_type': 'DOCUMENTARY',
                    'target_phase': 'Phase 1 – Governance',
                    'owner_role': 'Compliance Manager',
                    'reason': 'Automatisch aus sektoraler Ueberschneidung abgeleitet.',
                },
            )

        sector_packages = {
            'DIGITAL': [
                ('Sektorpaket Digital – Cloud- und Shared-Responsibility-Nachweise etablieren', 'CLOUD', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 2 – Transparenz', 'Architekturbeschreibungen, Provider-Controls und Verantwortungsabgrenzungen je Cloud-Dienst dokumentieren.'),
                ('Sektorpaket Digital – Erkennung, Logging und Incident Response operationalisieren', 'DETECT', 'CRITICAL', 'LARGE', 'TECHNICAL', 'Phase 4 – Quick Wins', 'Fuer digitale Dienste sind Erkennung, Alarmierung und Incident-Handhabung besonders zentral.'),
            ],
            'FINANCE': [
                ('Sektorpaket Finance – Governance, Nachweisfuehrung und Pruefpfade verdichten', 'DOC', 'HIGH', 'MEDIUM', 'DOCUMENTARY', 'Phase 1 – Governance', 'Kontrollnachweise, Freigaben und Review-Pfade sektorbezogen strukturiert aufbauen.'),
            ],
            'CRITICAL_INFRA': [
                ('Sektorpaket Kritische Infrastruktur – Resilienz, BCM und Wiederanlauf testen', 'BCM', 'HIGH', 'LARGE', 'TECHNICAL', 'Phase 5 – Strukturmassnahmen', 'Fuer kritische Versorgung und KRITIS-nahe Sektoren sind Resilienz und Wiederanlauf evidenzpflichtig.'),
            ],
        }
        for package in EvidenceNeedService.get_sector_packages(session.tenant):
            for title, domain_code, priority, effort, measure_type, target_phase, desc in sector_packages.get(package, []):
                session.generated_measures.get_or_create(
                    title=title,
                    defaults={
                        'domain': sector_domain_map.get(domain_code),
                        'description': desc,
                        'priority': priority,
                        'effort': effort,
                        'measure_type': measure_type,
                        'target_phase': target_phase,
                        'owner_role': 'ISMS Manager',
                        'reason': f'Sektorpaket {package} automatisch aus Sektorauswahl abgeleitet.',
                    },
                )

        # Sektorspezifische Zusatzmassnahmen
        if sector.code in {'DIGITAL_INFRASTRUCTURE', 'ICT_SERVICE_MANAGEMENT', 'DIGITAL_PROVIDERS', 'MSSP'}:
            session.generated_measures.get_or_create(
                title='Logging, Angriffserkennung und sichere Betriebsprozesse fuer digitale Dienste vertiefen',
                defaults={
                    'domain': sector_domain_map.get('DETECT'),
                    'description': 'Fuer digitale und IKT-nahe Sektoren sollte die Readiness von Monitoring, Erkennung, Incident Response und sicheren Betriebsprozessen priorisiert werden.',
                    'priority': 'CRITICAL',
                    'effort': 'LARGE',
                    'measure_type': 'TECHNICAL',
                    'target_phase': 'Phase 4 – Quick Wins',
                    'owner_role': 'Security Officer',
                    'reason': 'Sektoraler Schwerpunkt auf digitale Kernservices.',
                },
            )
        elif sector.code in {'ENERGY', 'HYDROGEN', 'TRANSPORT', 'HEALTH', 'DRINKING_WATER', 'WASTEWATER', 'CHEMICALS', 'FOOD'}:
            session.generated_measures.get_or_create(
                title='Betriebsresilienz, BCM und physische Sicherheit sektorbezogen konkretisieren',
                defaults={
                    'domain': sector_domain_map.get('BCM') or sector_domain_map.get('PHYS'),
                    'description': 'Fuer den gewaehlten Sektor sollten Wiederanlauf, physische Schutzmassnahmen, kritische Lieferketten und Eskalationswege besonders frueh detailliert werden.',
                    'priority': 'HIGH',
                    'effort': 'LARGE',
                    'measure_type': 'ORGANIZATIONAL',
                    'target_phase': 'Phase 5 – Strukturmassnahmen',
                    'owner_role': 'ISMS Manager',
                    'reason': 'Sektoraler Schwerpunkt auf Resilienz und Versorgungssicherheit.',
                },
            )
        elif sector.code in {'BANKING', 'FINANCIAL_MARKET_INFRASTRUCTURE'}:
            session.generated_measures.get_or_create(
                title='Governance-, Nachweis- und Meldeprozesse mit Finanzsektor-Fokus schaerfen',
                defaults={
                    'domain': sector_domain_map.get('DOC') or sector_domain_map.get('INC'),
                    'description': 'Fuer Finanzsektoren sollten Nachweisfaehigkeit, Governance und Vorfallprozesse frueh mit sektoralen Anforderungen abgeglichen werden.',
                    'priority': 'HIGH',
                    'effort': 'MEDIUM',
                    'measure_type': 'DOCUMENTARY',
                    'target_phase': 'Phase 1 – Governance',
                    'owner_role': 'Compliance Manager',
                    'reason': 'Sektoraler Schwerpunkt auf Nachweis- und Meldepflichten.',
                },
            )

    @staticmethod
    def _generate_country_specific_measures(session: AssessmentSession):
        country_context = WizardService.get_country_context(session.tenant)
        if country_context['is_multi_country']:
            session.generated_measures.get_or_create(
                title='Laenderuebergreifende Governance, Rollen und Eskalationswege harmonisieren',
                defaults={
                    'description': f'Das Unternehmen ist in mehreren Laendern aktiv ({country_context["display"]}). Policies, Eskalationswege, Incident-Kommunikation und Verantwortlichkeiten sollten harmonisiert werden.',
                    'priority': 'HIGH',
                    'effort': 'MEDIUM',
                    'measure_type': 'ORGANIZATIONAL',
                    'target_phase': 'Phase 1 – Governance',
                    'owner_role': 'ISMS Manager',
                    'reason': 'Automatisch aus Multi-Country-Auswahl abgeleitet.',
                },
            )
        if country_context['has_non_eu_eea']:
            session.generated_measures.get_or_create(
                title='Drittlandbezuege, Lieferkette und Datenfluesse strukturiert pruefen',
                defaults={
                    'description': 'Nicht-EU-/EWR-Laender wurden ausgewaehlt. Pruefen Sie Datenfluesse, externe Dienstleister, Support-Modelle und zusaetzliche vertragliche bzw. organisatorische Schutzmassnahmen.',
                    'priority': 'HIGH',
                    'effort': 'MEDIUM',
                    'measure_type': 'DOCUMENTARY',
                    'target_phase': 'Phase 5 – Strukturmassnahmen',
                    'owner_role': 'Compliance Manager',
                    'reason': 'Automatisch aus Laender-/Drittlandkontext abgeleitet.',
                },
            )

    @staticmethod
    def _build_executive_summary(session: AssessmentSession, domain_scores: List[DomainScore]) -> str:
        average = int(sum(item.score_percent for item in domain_scores) / len(domain_scores)) if domain_scores else 0
        gaps = session.generated_gaps.count()
        measures = session.generated_measures.count()
        sector = get_sector_definition(session.tenant.sector)
        country_context = WizardService.get_country_context(session.tenant)
        size_info = _classify_company_size(session.tenant)
        product_summary = ProductSecurityService.build_summary(session.tenant)

        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            return (
                f'Die Vorpruefung fuer {session.tenant.name} im Sektor {sector.label} liefert die Indikation: {session.applicability_result}. '
                f'Unternehmensgroesse: {size_info["size_label"]}. '
                f'Operative Laender/Prasenzen: {country_context["display"]}. {country_context["geo_impact"]} '
                f'{product_summary}'
            )
        if session.assessment_type == AssessmentSession.Type.ISO_READINESS:
            return (
                f'Das ISO-27001-Readiness-Assessment fuer {session.tenant.name} im Sektor {sector.label} ergibt aktuell eine durchschnittliche Readiness von {average}%. '
                f'Dabei wurden {gaps} relevante Gaps und {measures} priorisierte Massnahmen identifiziert. '
                f'Operative Laender/Prasenzen: {country_context["display"]}. {country_context["geo_impact"]} '
                f'{product_summary}'
            )
        return (
            f'Das vollstaendige Assessment fuer {session.tenant.name} im Sektor {sector.label} ergibt aktuell eine durchschnittliche Readiness von {average}%. '
            f'Dabei wurden {gaps} relevante Gaps und {measures} priorisierte Massnahmen identifiziert. '
            f'Die Einordnung zur regulatorischen Naehe lautet: {session.applicability_result or "noch nicht bewertet"}. '
            f'Sektoraler Schwerpunkt: {", ".join(sector.roadmap_focus[:3])}. '
            f'Operative Laender/Prasenzen: {country_context["display"]}. {country_context["geo_impact"]} '
            f'{sector.downstream_impact} {product_summary}'
        )

    # ── F17: Dynamische Roadmap-Phasen basierend auf Reifegrad und Groesse ──

    @staticmethod
    def _calculate_phase_duration(base_weeks: int, average_readiness: int, size_info: dict) -> int:
        """F17: Phasendauer an Reifegrad und Unternehmensgroesse koppeln."""
        factor = 1.0
        if average_readiness < 30:
            factor *= 1.5
        elif average_readiness > 70:
            factor *= 0.7
        if size_info.get('is_large'):
            factor *= 1.3
        elif size_info.get('is_small'):
            factor *= 0.8
        return max(1, round(base_weeks * factor))

    @staticmethod
    def _generate_roadmap(session: AssessmentSession):
        start_date = timezone.localdate()
        sector = get_sector_definition(session.tenant.sector)
        country_context = WizardService.get_country_context(session.tenant)
        mode_context = WizardService.get_mode_context(session)
        size_info = _classify_company_size(session.tenant)

        # F17: Durchschnittliche Readiness fuer Phasendauer-Berechnung
        ds = list(session.domain_scores.all())
        avg_readiness = int(sum(d.score_percent for d in ds) / len(ds)) if ds else 30

        plan = RoadmapPlan.objects.create(
            tenant=session.tenant, session=session,
            title=f'Roadmap fuer {session.tenant.name}',
            summary=(
                f'Automatisch abgeleitete Umsetzungsroadmap fuer den Modus {mode_context["title"]} basierend auf Assessment, Gaps, Massnahmen, der Sektorauswahl {sector.label} '
                f'und den operativen Laendern {country_context["display"]}.'
            ),
            overall_priority='HIGH' if session.generated_measures.filter(priority__in=['CRITICAL', 'HIGH']).exists() else 'MEDIUM',
            planned_start=start_date,
        )
        phase_map = {}
        phase_start = start_date
        phase_sequence = WizardService.PHASE_SEQUENCE

        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            phase_sequence = [
                ('Phase 1 – Vorpruefung', 'Unternehmensprofil, Sektor, Schwellenwerte und Laender kontextualisieren.', 1),
                ('Phase 2 – Validierung', 'Betroffenheitsindikation mit Compliance/Legal und Konzernsicht pruefen.', 2),
                ('Phase 3 – Anschlussentscheidung', 'Entscheiden, ob NIS2-Folgeprojekt oder ISO-27001-first gestartet wird.', 1),
            ]
        elif session.assessment_type == AssessmentSession.Type.ISO_READINESS:
            phase_sequence = [
                ('Phase 1 – Governance', 'Scope, Verantwortlichkeiten und Management-Commitment festlegen.', 2),
                ('Phase 2 – Transparenz', 'Geschaeftsbereiche, Prozesse, Assets und Lieferanten erfassen.', 3),
                ('Phase 3 – Gap-Analyse', 'ISO-orientierte Domaenen bewerten und Massnahmen priorisieren.', 2),
                ('Phase 4 – Strukturmassnahmen', 'Policies, Controls, SDLC und Resilienz nachhaltig staerken.', 6),
                ('Phase 5 – Audit Readiness', 'Management Review, Nachweise und Zertifizierungsfaehigkeit vorbereiten.', 2),
            ]

        for idx, (name, objective, base_weeks) in enumerate(phase_sequence, start=1):
            # F17: Dynamische Wochen
            weeks = WizardService._calculate_phase_duration(base_weeks, avg_readiness, size_info)
            sector_objective = objective
            if name == 'Phase 3 – Gap-Analyse':
                sector_objective = f'{objective} Zusaetzlicher Sektor-Fokus: {", ".join(sector.roadmap_focus[:2])}.'
            if country_context['is_multi_country'] and 'Governance' in name:
                sector_objective += ' Zusaetzlich muessen laenderuebergreifende Rollen, Eskalationswege und harmonisierte Policies festgelegt werden.'
            if country_context['has_non_eu_eea'] and 'Strukturmassnahmen' in name:
                sector_objective += ' Drittlandbezuege, Lieferkette und Datenfluesse sind gesondert zu pruefen.'
            if session.tenant.develops_digital_products and ('Governance' in name or 'Strukturmassnahmen' in name or 'Gap-Analyse' in name):
                sector_objective += ' Product Security, Secure Development, Vulnerability Handling und Release-/Support-Verantwortung muessen mitberuecksichtigt werden.'
            phase_end = phase_start + timedelta(weeks=weeks) - timedelta(days=1)
            phase_map[name] = RoadmapPhase.objects.create(
                plan=plan, name=name, sort_order=idx * 10,
                objective=sector_objective, duration_weeks=weeks,
                planned_start=phase_start, planned_end=phase_end,
            )
            phase_start = phase_end + timedelta(days=1)

        ordered_phases = list(phase_map.values())
        phase_task_map = {phase.id: [] for phase in ordered_phases}
        for index, measure in enumerate(session.generated_measures.all(), start=1):
            phase = phase_map.get(measure.target_phase) or ordered_phases[0]
            planned_start = phase.planned_start or start_date
            due_days = 30 if measure.priority == 'CRITICAL' else 60 if measure.priority == 'HIGH' else 90 if measure.priority == 'MEDIUM' else 120
            task = RoadmapTask.objects.create(
                phase=phase, measure=measure, title=measure.title,
                description=measure.description, priority=measure.priority,
                owner_role=measure.owner_role, due_in_days=due_days,
                dependency_text='Vor Umsetzung sollten Verantwortlichkeiten und Scope geklaert sein.' if 'Governance' not in phase.name else '',
                status=RoadmapTask.Status.PLANNED,
                planned_start=planned_start + timedelta(days=(index - 1) % 14),
                due_date=planned_start + timedelta(days=due_days),
                notes='Automatisch generierte Aufgabe aus dem Assessment. Bitte konkretisieren und mit Evidenzen unterlegen.',
            )
            phase_task_map[phase.id].append(task)

        sector_phase = phase_map.get('Phase 1 – Governance') or ordered_phases[0]
        sector_task, _ = RoadmapTask.objects.get_or_create(
            phase=sector_phase,
            title=f'Sektorprofil {sector.label} validieren und dokumentieren',
            defaults={
                'description': f'Dokumentieren, warum der ausgewaehlte Sektor {sector.label} gewaehlt wurde und welche Auswirkungen dies auf Betroffenheit, Scope und Massnahmen hat.',
                'priority': 'HIGH' if sector.score_bonus else 'MEDIUM',
                'owner_role': 'Compliance Manager',
                'due_in_days': 21,
                'status': RoadmapTask.Status.PLANNED,
                'planned_start': sector_phase.planned_start,
                'due_date': (sector_phase.planned_start or start_date) + timedelta(days=21),
                'notes': sector.downstream_impact,
            },
        )
        phase_task_map[sector_phase.id].append(sector_task)

        # Dependency graph
        governance_anchor = sector_task
        for idx, phase in enumerate(ordered_phases):
            current_tasks = phase_task_map.get(phase.id, [])
            if not current_tasks:
                continue
            if idx > 0:
                previous_phase = ordered_phases[idx - 1]
                previous_tasks = phase_task_map.get(previous_phase.id, [])
                predecessors = previous_tasks[:2] or ([governance_anchor] if governance_anchor else [])
                for task in current_tasks[:4]:
                    for predecessor in predecessors[:2]:
                        if predecessor.id == task.id:
                            continue
                        RoadmapTaskDependency.objects.get_or_create(
                            predecessor=predecessor, successor=task,
                            defaults={
                                'dependency_type': RoadmapTaskDependency.DependencyType.FINISH_TO_START,
                                'rationale': f'Phase {task.phase.name} baut auf Ergebnissen aus {predecessor.phase.name} auf.',
                            },
                        )
                    task.dependency_text = '; '.join(pre.title for pre in predecessors[:2])
                    task.save(update_fields=['dependency_text'])
            anchor = next((t for t in current_tasks if t.priority in {'CRITICAL', 'HIGH'}), current_tasks[0])
            for task in current_tasks[1:4]:
                if anchor.id == task.id:
                    continue
                RoadmapTaskDependency.objects.get_or_create(
                    predecessor=anchor, successor=task,
                    defaults={
                        'dependency_type': RoadmapTaskDependency.DependencyType.START_TO_START,
                        'rationale': 'Innerhalb der Phase sollten priorisierte Arbeitspakete vor nachgelagerten Aufgaben beginnen.',
                    },
                )
        return plan

    @staticmethod
    def _build_next_steps(session: AssessmentSession):
        measures = list(session.generated_measures.all().order_by('priority', 'created_at'))
        return {
            'next_30_days': [{'title': m.title, 'priority': m.priority} for m in measures if m.priority == 'CRITICAL'][:5],
            'next_60_days': [{'title': m.title, 'priority': m.priority} for m in measures if m.priority in {'CRITICAL', 'HIGH'}][:5],
            'next_90_days': [{'title': m.title, 'priority': m.priority} for m in measures if m.priority in {'MEDIUM', 'LOW'}][:5],
        }

    @staticmethod
    def _generate_report(session: AssessmentSession, domain_scores: List[DomainScore]):
        average = int(sum(item.score_percent for item in domain_scores) / len(domain_scores)) if domain_scores else 0
        measures = list(session.generated_measures.values('title', 'priority', 'target_phase')[:10])
        gaps = list(session.generated_gaps.values('title', 'severity')[:10])
        plan = session.roadmap_plans.first()
        sector = get_sector_definition(session.tenant.sector)
        country_context = WizardService.get_country_context(session.tenant)
        roadmap_summary = list(plan.phases.values('name', 'duration_weeks', 'objective')) if plan else []
        domain_scores_json = [
            {'domain': item.domain.name, 'score_percent': item.score_percent, 'maturity_level': item.maturity_level}
            for item in domain_scores
        ]
        top_measures = [
            {'title': 'Sektor-Fokus: ' + sector.label, 'priority': sector.indicative_classification, 'target_phase': 'Governance'}
        ] + measures
        dependency_summary = []
        if plan:
            for dep in RoadmapTaskDependency.objects.filter(successor__phase__plan=plan).select_related('predecessor', 'successor')[:12]:
                dependency_summary.append({
                    'predecessor': dep.predecessor.title, 'successor': dep.successor.title,
                    'type': dep.dependency_type, 'rationale': dep.rationale,
                })

        # F16: NIS2-Readiness separat berechnen basierend auf NIS2-relevanten Fragen
        nis2_percent = WizardService._calculate_nis2_readiness(session, domain_scores)
        product_matrix = ProductSecurityService.get_regime_matrix(session.tenant)
        framework_readiness = ProductSecurityService.calculate_framework_readiness(session)

        return ReportSnapshot.objects.create(
            tenant=session.tenant, session=session,
            title=f'Report {session.tenant.name}',
            executive_summary=(session.executive_summary or '') + f' Laenderkontext: {country_context["display"]}.',
            applicability_result=session.applicability_result,
            iso_readiness_percent=average,
            nis2_readiness_percent=nis2_percent,
            cra_readiness_percent=framework_readiness['cra_readiness_percent'],
            ai_act_readiness_percent=framework_readiness['ai_act_readiness_percent'],
            iec62443_readiness_percent=framework_readiness['iec62443_readiness_percent'],
            iso_sae_21434_readiness_percent=framework_readiness['iso_sae_21434_readiness_percent'],
            regulatory_matrix_json=product_matrix,
            product_security_json={
                'summary': product_matrix['summary'],
                'product_security_scope': session.tenant.product_security_scope,
                'flags': {
                    'develops_digital_products': session.tenant.develops_digital_products,
                    'uses_ai_systems': session.tenant.uses_ai_systems,
                    'ot_iacs_scope': session.tenant.ot_iacs_scope,
                    'automotive_scope': session.tenant.automotive_scope,
                    'psirt_defined': session.tenant.psirt_defined,
                    'sbom_required': session.tenant.sbom_required,
                },
            },
            top_gaps_json=gaps,
            top_measures_json=top_measures[:10],
            roadmap_summary=roadmap_summary,
            domain_scores_json=domain_scores_json,
            next_steps_json={**WizardService._build_next_steps(session), 'dependencies': dependency_summary},
        )

    @staticmethod
    def _calculate_nis2_readiness(session: AssessmentSession, domain_scores: List[DomainScore]) -> int:
        """F16: NIS2-Readiness basierend auf tatsaechlich NIS2-relevanten Fragen berechnen.

        Anstatt den ISO-Durchschnitt mit einem Sektor-Bonus zu addieren (was fachlich
        keinen Sinn ergibt), berechnen wir den Erfuellungsgrad der NIS2-markierten Fragen.
        """
        if session.assessment_type == AssessmentSession.Type.ISO_READINESS:
            return 0  # Kein NIS2-Score im reinen ISO-Modus
        if session.assessment_type == AssessmentSession.Type.APPLICABILITY:
            # Fuer den Applicability-Modus: Score aus der Betroffenheitspruefung normalisieren
            total = session.answers.filter(question__question_kind=AssessmentQuestion.Kind.APPLICABILITY).count()
            if total == 0:
                return 0
            score = sum(a.score for a in session.answers.filter(question__question_kind=AssessmentQuestion.Kind.APPLICABILITY))
            max_score = total * 5
            return min(100, int((score / max_score) * 100)) if max_score else 0

        # FULL-Modus: Nur NIS2-relevante Maturity-Fragen heranziehen
        nis2_answers = session.answers.filter(
            question__question_kind=AssessmentQuestion.Kind.MATURITY,
            question__applies_to_nis2=True,
        ).exclude(
            # F08: N/A ausschliessen
            selected_option__is_na=True,
        )
        total = nis2_answers.count()
        if total == 0:
            return 0
        score = sum(a.score for a in nis2_answers)
        max_score = total * 5
        return min(100, int((score / max_score) * 100)) if max_score else 0
