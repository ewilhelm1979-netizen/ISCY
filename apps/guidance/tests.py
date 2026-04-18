import json
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.assessments.models import ApplicabilityAssessment, Assessment, Measure
from apps.guidance.services import JourneyService
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.requirements_app.models import Requirement
from apps.risks.models import Risk


@override_settings(
    GUIDANCE_SCORING_BACKEND='local',
    RUST_BACKEND_URL='',
    RUST_STRICT_MODE=False,
)
class SocPlaybookGuidanceIntegrationTests(TestCase):
    def setUp(self):
        call_command('seed_guidance')

        self.tenant = Tenant.objects.create(
            name='Tenant SOC',
            slug='tenant-soc',
            country='DE',
            description='Tenant fuer SOC-Playbook-Test',
            sector='OTHER',
        )

        ApplicabilityAssessment.objects.create(
            tenant=self.tenant,
            sector='IT',
            company_size='SME',
            critical_services='SOC Monitoring',
            supply_chain_role='Provider',
            status=ApplicabilityAssessment.Status.RELEVANT,
            reasoning='Testfall',
        )

        self.processes = [
            Process.objects.create(tenant=self.tenant, name='Incident Intake'),
            Process.objects.create(tenant=self.tenant, name='Triage & Korrelation'),
            Process.objects.create(tenant=self.tenant, name='Containment & Recovery'),
        ]

        Risk.objects.create(
            tenant=self.tenant,
            process=self.processes[0],
            title='Credential Phishing',
            description='Unbehandeltes Credential Phishing kann zu Account Compromise fuehren.',
        )

        self.requirement = Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.24',
            title='Incident Management',
            domain='Incident',
            description='Incident-Prozess und Eskalationswege sind etabliert.',
            is_active=True,
        )
        Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.25',
            title='Response',
            domain='Incident',
            description='Response geplant',
            is_active=True,
        )
        Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.26',
            title='Learning',
            domain='Incident',
            description='Lessons learned etabliert',
            is_active=True,
        )
        Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.27',
            title='Improvement',
            domain='Incident',
            description='Kontinuierliche Verbesserung',
            is_active=True,
        )
        Assessment.objects.create(
            tenant=self.tenant,
            process=self.processes[0],
            requirement=self.requirement,
            status=Assessment.Status.PARTIAL,
        )

    @override_settings(
        GUIDANCE_SCORING_BACKEND='local',
        RUST_BACKEND_URL='',
        RUST_STRICT_MODE=False,
    )
    def test_soc_playbook_step_is_current_without_measures(self):
        evaluation = JourneyService.evaluate_tenant(self.tenant)

        self.assertIsNotNone(evaluation['state'].current_step)
        self.assertEqual(evaluation['state'].current_step.code, 'soc_phishing_playbook_applied')
        self.assertIn('SOC-Playbook', '\n'.join(evaluation['todo_items']))

    @override_settings(
        GUIDANCE_SCORING_BACKEND='local',
        RUST_BACKEND_URL='',
        RUST_STRICT_MODE=False,
    )
    def test_soc_playbook_step_is_done_when_measure_exists(self):
        Measure.objects.create(
            tenant=self.tenant,
            assessment=Assessment.objects.filter(tenant=self.tenant).first(),
            title='Phishing-Mails tenantweit entfernen',
            description='Containment gem. SOC-Playbook',
            priority=Measure.Priority.HIGH,
            status=Measure.Status.IN_PROGRESS,
        )

        evaluation = JourneyService.evaluate_tenant(self.tenant)

        self.assertIsNone(evaluation['state'].current_step)
        self.assertEqual(evaluation['state'].progress_percent, 100)

    @patch('apps.guidance.services.urlopen')
    def test_rust_guidance_bridge_is_used_when_available(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'current_step_code': 'soc_phishing_playbook_applied',
            'summary': 'Rust summary',
            'next_action_text': 'Rust next action',
            'todo_items': ['Rust todo'],
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx

        with self.settings(RUST_BACKEND_URL='http://rust-backend:9000', GUIDANCE_SCORING_BACKEND='rust_service'):
            evaluation = JourneyService.evaluate_tenant(self.tenant)

        self.assertEqual(evaluation['state'].summary, 'Rust summary')
        self.assertEqual(evaluation['state'].next_action_text, 'Rust next action')
        self.assertEqual(evaluation['todo_items'], ['Rust todo'])

    def test_rust_guidance_bridge_raises_in_strict_mode_without_backend(self):
        with self.settings(RUST_BACKEND_URL='', GUIDANCE_SCORING_BACKEND='rust_service', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                JourneyService.evaluate_tenant(self.tenant)

    def test_rust_guidance_bridge_raises_without_legacy_fallback_even_if_not_strict(self):
        with self.settings(
            RUST_BACKEND_URL='',
            GUIDANCE_SCORING_BACKEND='rust_service',
            RUST_STRICT_MODE=False,
        ):
            with self.assertRaises(RuntimeError):
                JourneyService.evaluate_tenant(self.tenant)

    def test_collect_tenant_snapshot_returns_expected_counts(self):
        snapshot = JourneyService._collect_tenant_snapshot(self.tenant)
        self.assertEqual(snapshot.process_count, 3)
        self.assertEqual(snapshot.risk_count, 1)
        self.assertEqual(snapshot.assessment_count, 1)
        self.assertEqual(snapshot.measure_count, 0)
        self.assertEqual(snapshot.applicability_count, 1)
