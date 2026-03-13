from django.urls import NoReverseMatch, reverse
from apps.assessments.models import ApplicabilityAssessment, Assessment, Measure
from apps.guidance.models import GuidanceStep, TenantJourneyState
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.requirements_app.models import Requirement
from apps.risks.models import Risk


class JourneyService:
    @staticmethod
    def get_default_tenant(user=None):
        if user and getattr(user, 'tenant_id', None):
            tenant = Tenant.objects.filter(pk=user.tenant_id).first()
            if tenant:
                return tenant
        return Tenant.objects.first()

    @staticmethod
    def get_or_create_state(tenant: Tenant) -> TenantJourneyState:
        state, _ = TenantJourneyState.objects.get_or_create(tenant=tenant)
        return state

    @staticmethod
    def evaluate_tenant(tenant: Tenant, user=None):
        state = JourneyService.get_or_create_state(tenant)
        steps = list(GuidanceStep.objects.filter(is_active=True).order_by('sort_order'))

        process_count = Process.objects.filter(tenant=tenant).count()
        risk_count = Risk.objects.filter(tenant=tenant).count()
        assessment_count = Assessment.objects.filter(tenant=tenant).count()
        measure_open_count = Measure.objects.filter(tenant=tenant).exclude(status=Measure.Status.DONE).count()
        applicability_count = ApplicabilityAssessment.objects.filter(tenant=tenant).count()
        requirement_count = Requirement.objects.filter(is_active=True).count()

        completed = 0
        current_step = None
        for step in steps:
            if JourneyService._is_step_done(step.code, tenant, process_count, risk_count, assessment_count, applicability_count, requirement_count):
                completed += 1
            elif current_step is None:
                current_step = step

        if not steps:
            state.current_step = None
            state.last_completed_step = None
            state.progress_percent = 0
            state.summary = 'Es sind keine Guided Steps konfiguriert.'
            state.next_action_text = 'Bitte Guidance Steps anlegen.'
            state.updated_by = user
            state.save()
            return {
                'state': state,
                'next_step_url': '',
                'next_step_label': '',
                'todo_items': [],
            }

        state.progress_percent = int((completed / len(steps)) * 100)
        state.current_step = current_step
        state.last_completed_step = steps[completed - 1] if completed > 0 else None
        state.summary, state.next_action_text = JourneyService._build_step_message(
            current_step.code if current_step else '', tenant, process_count, risk_count, assessment_count, measure_open_count, applicability_count
        ) if current_step else (
            'Alle aktuell definierten Guided Steps sind abgeschlossen.',
            'Nächster sinnvoller Schritt: Evidenzen, Reviews und Audit-Vorbereitung vertiefen.',
        )
        state.updated_by = user
        state.save()

        todo_items = JourneyService._todo_items(tenant, process_count, risk_count, assessment_count, measure_open_count, applicability_count)
        next_step_url = JourneyService._resolve_route(current_step.route_name) if current_step and current_step.route_name else ''
        next_step_label = current_step.cta_label if current_step and current_step.cta_label else 'Zum Schritt'
        return {
            'state': state,
            'next_step_url': next_step_url,
            'next_step_label': next_step_label,
            'todo_items': todo_items,
        }

    @staticmethod
    def _resolve_route(route_name: str) -> str:
        try:
            return reverse(route_name)
        except NoReverseMatch:
            return ''

    @staticmethod
    def _is_step_done(code: str, tenant: Tenant, process_count: int, risk_count: int, assessment_count: int, applicability_count: int, requirement_count: int) -> bool:
        if code == 'applicability_checked':
            return applicability_count >= 1
        if code == 'company_scope_defined':
            return bool(tenant.description and tenant.sector)
        if code == 'requirements_available':
            return requirement_count >= 4
        if code == 'initial_processes_captured':
            return process_count >= 3
        if code == 'initial_risks_captured':
            return risk_count >= 1
        if code == 'initial_assessment_done':
            return assessment_count >= 1
        return False

    @staticmethod
    def _build_step_message(code: str, tenant: Tenant, process_count: int, risk_count: int, assessment_count: int, measure_open_count: int, applicability_count: int):
        if code == 'applicability_checked':
            return (
                'Starten Sie mit der Betroffenheitsanalyse. Erst damit wird klar, ob ISO-27001-Readiness ausreicht oder NIS2-/KRITIS-Nähe vertieft werden sollte.',
                'Bewerten Sie Sektor, Größe, kritische Dienstleistungen und Lieferkettenrolle.',
            )
        if code == 'company_scope_defined':
            return (
                'Definieren Sie den Scope des ISMS. Ohne Scope sind spätere Bewertungen fachlich unscharf und für Audits schwer belastbar.',
                'Pflegen Sie Beschreibung, Zielbild, Sektor und kritische Leistungen des Unternehmens.',
            )
        if code == 'requirements_available':
            return (
                'Es fehlen Requirement-Grundlagen. Ohne die ISCY Requirement Library ist kein belastbares Mapping gegen ISO 27001 oder NIS2 moeglich.',
                'Stellen Sie sicher, dass die ISCY Requirement Library initial geladen wurde.',
            )
        if code == 'initial_processes_captured':
            return (
                f'Derzeit sind {process_count} Prozesse erfasst. Für einen belastbaren Einstieg sollten mindestens 3 kritische Prozesse dokumentiert werden.',
                'Erfassen Sie die wichtigsten Geschäfts- oder IT-Prozesse inklusive Owner und Kritikalität.',
            )
        if code == 'initial_risks_captured':
            return (
                f'Derzeit sind {risk_count} Risiken erfasst. Ohne erste Risiken bleibt die Ableitung von Maßnahmen zu flach.',
                'Erfassen Sie mindestens ein initiales Risiko zu einem kritischen Prozess oder Asset.',
            )
        if code == 'initial_assessment_done':
            return (
                f'Es gibt aktuell {assessment_count} Assessments und {measure_open_count} offene Maßnahmen. Erst Assessments zeigen, was ausreichend ist und wo echte Gaps bestehen.',
                'Starten Sie die erste Prozess- oder Requirement-Bewertung.',
            )
        return (
            'Es gibt einen offenen Guided Step.',
            'Prüfen Sie die geführte Umsetzungslogik.',
        )

    @staticmethod
    def _todo_items(tenant: Tenant, process_count: int, risk_count: int, assessment_count: int, measure_open_count: int, applicability_count: int):
        items = []
        if applicability_count == 0:
            items.append('Betroffenheitsanalyse anlegen')
        if not tenant.description:
            items.append('ISMS-Scope und Unternehmensbeschreibung pflegen')
        if process_count < 3:
            items.append(f'Noch {3 - process_count} kritische Prozesse erfassen')
        if risk_count < 1:
            items.append('Mindestens ein Risiko dokumentieren')
        if assessment_count < 1:
            items.append('Erstes Assessment durchführen')
        if measure_open_count > 0:
            items.append(f'{measure_open_count} offene Maßnahmen nachverfolgen')
        return items

    @staticmethod
    def phase_progress():
        phases = []
        for phase_key, phase_label in GuidanceStep._meta.get_field('phase').choices:
            total = GuidanceStep.objects.filter(phase=phase_key, is_active=True).count()
            phases.append({'key': phase_key, 'label': phase_label, 'total_steps': total})
        return phases
