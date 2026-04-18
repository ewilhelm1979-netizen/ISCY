import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.catalog.models import AssessmentDomain
from apps.organizations.models import Tenant
from apps.reports.models import ReportSnapshot
from apps.roadmap.models import RoadmapPhase, RoadmapPlan
from apps.wizard.models import AssessmentSession, DomainScore, GeneratedGap, GeneratedMeasure


User = get_user_model()


@override_settings(WIZARD_RESULTS_BACKEND='local', RUST_BACKEND_URL='')
class WizardViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(
            name='Tenant A',
            slug='tenant-a',
            country='DE',
            operation_countries=['DE'],
            sector='MSSP',
        )
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-wizard',
            email='wizard-user@example.test',
            password='testpass123',
            tenant=self.tenant_a,
            first_name='Ada',
            last_name='Lovelace',
        )
        self.user_b = User.objects.create_user(
            username='tenant-b-wizard',
            password='testpass123',
            tenant=self.tenant_b,
        )
        self.session_a = AssessmentSession.objects.create(
            tenant=self.tenant_a,
            started_by=self.user_a,
            assessment_type=AssessmentSession.Type.FULL,
            status=AssessmentSession.Status.COMPLETED,
            current_step=AssessmentSession.Step.RESULTS,
            applicability_result='NIS2 relevant',
            applicability_reasoning='Critical managed service provider',
            executive_summary='Executive summary from wizard',
            progress_percent=100,
        )
        self.session_b = AssessmentSession.objects.create(
            tenant=self.tenant_b,
            started_by=self.user_b,
            assessment_type=AssessmentSession.Type.FULL,
        )
        self.domain = AssessmentDomain.objects.create(
            code='GOV',
            name='Governance',
            sort_order=1,
        )
        DomainScore.objects.create(
            session=self.session_a,
            domain=self.domain,
            score_raw=8,
            score_percent=80,
            maturity_level='Managed',
            gap_level='LOW',
        )
        GeneratedGap.objects.create(
            session=self.session_a,
            domain=self.domain,
            severity=GeneratedGap.Severity.HIGH,
            title='MFA-Abdeckung fehlt',
            description='MFA is not consistently enforced.',
        )
        GeneratedMeasure.objects.create(
            session=self.session_a,
            domain=self.domain,
            title='MFA ausrollen',
            description='Roll out MFA.',
            priority=GeneratedMeasure.Priority.CRITICAL,
            effort=GeneratedMeasure.Effort.MEDIUM,
            measure_type=GeneratedMeasure.Type.TECHNICAL,
            target_phase='30 Tage',
            owner_role='IAM Lead',
        )
        self.report = ReportSnapshot.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            title='April Readiness',
            executive_summary='Report summary',
            applicability_result='NIS2 relevant',
            iso_readiness_percent=80,
            nis2_readiness_percent=75,
            domain_scores_json=[{'domain': 'Governance', 'score_percent': 80, 'maturity_level': 'Managed'}],
            regulatory_matrix_json={'summary': 'applicable'},
            compliance_versions_json={},
            product_security_json={},
            next_steps_json={'dependencies': [], 'next_30_days': [], 'next_60_days': [], 'next_90_days': []},
        )
        self.plan = RoadmapPlan.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            title='Security Roadmap',
            summary='Roadmap summary',
            overall_priority='HIGH',
        )
        RoadmapPhase.objects.create(
            plan=self.plan,
            name='Governance Phase',
            sort_order=1,
            objective='Create governance.',
            duration_weeks=2,
        )

    def test_wizard_start_uses_local_sessions_by_default(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('wizard:start'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['sessions']), [self.session_a])
        self.assertEqual(response.context['wizard_results_source'], 'django')

    @patch('apps.wizard.services.urlopen')
    def test_wizard_start_can_use_rust_session_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, {
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'sessions': [self._rust_session_payload(assessment_type='ISO_READINESS')],
        })
        self.client.force_login(self.user_a)

        with self.settings(WIZARD_RESULTS_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('wizard:start'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/wizard/sessions')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(response.context['wizard_results_source'], 'rust_service')
        self.assertEqual(list(response.context['sessions'])[0].assessment_type, 'ISO_READINESS')

    @patch('apps.wizard.services.urlopen')
    def test_wizard_results_can_use_rust_result_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_results_payload())
        self.client.force_login(self.user_a)

        with self.settings(WIZARD_RESULTS_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('wizard:results', kwargs={'pk': self.session_a.id}))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f'http://rust-backend:9000/api/v1/wizard/sessions/{self.session_a.id}/results',
        )
        self.assertEqual(response.context['wizard_results_source'], 'rust_service')
        self.assertEqual(response.context['session'].executive_summary, 'Rust Executive Summary')
        self.assertEqual(response.context['report'].title, 'Rust Report')
        self.assertEqual(response.context['plan'].title, 'Rust Roadmap')
        self.assertEqual(response.context['domain_scores'][0].domain.name, 'Governance')
        self.assertEqual(response.context['measures'][0].get_priority_display(), 'Kritisch')
        self.assertContains(response, 'Rust Executive Summary')
        self.assertContains(response, 'Governance Phase')

    @patch('apps.wizard.services.urlopen', side_effect=OSError('backend down'))
    def test_wizard_results_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            WIZARD_RESULTS_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('wizard:results', kwargs={'pk': self.session_a.id}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['wizard_results_source'], 'django')
        self.assertEqual(response.context['session'], self.session_a)

    def test_wizard_results_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(WIZARD_RESULTS_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('wizard:results', kwargs={'pk': self.session_a.id}))

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx

    def _rust_session_payload(self, **overrides):
        payload = {
            'id': self.session_a.id,
            'tenant_id': self.tenant_a.id,
            'tenant_name': self.tenant_a.name,
            'assessment_type': 'FULL',
            'assessment_type_label': 'Vollstaendige ISMS-/NIS2-Gap-Analyse',
            'status': 'COMPLETED',
            'status_label': 'Abgeschlossen',
            'current_step': 'results',
            'current_step_label': 'Ergebnis',
            'started_by_id': self.user_a.id,
            'started_by_display': 'Ada Lovelace',
            'applicability_result': 'NIS2 relevant',
            'applicability_reasoning': 'Critical managed service provider',
            'executive_summary': 'Rust Executive Summary',
            'progress_percent': 100,
            'completed_at': '2026-04-18T12:00:00Z',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload

    def _rust_results_payload(self):
        return {
            'api_version': 'v1',
            'session': self._rust_session_payload(),
            'report': {
                'id': self.report.id,
                'tenant_id': self.tenant_a.id,
                'session_id': self.session_a.id,
                'title': 'Rust Report',
                'executive_summary': 'Report summary',
                'applicability_result': 'NIS2 relevant',
                'iso_readiness_percent': 80,
                'nis2_readiness_percent': 75,
                'kritis_readiness_percent': 30,
                'cra_readiness_percent': 20,
                'ai_act_readiness_percent': 10,
                'iec62443_readiness_percent': 15,
                'iso_sae_21434_readiness_percent': 25,
                'regulatory_matrix_json': {'summary': 'applicable'},
                'compliance_versions_json': {},
                'product_security_json': {},
                'top_gaps_json': [{'title': 'MFA-Abdeckung fehlt'}],
                'top_measures_json': [{'title': 'MFA ausrollen', 'priority': 'CRITICAL'}],
                'roadmap_summary': [{'name': 'Governance'}],
                'domain_scores_json': [{'domain': 'Governance', 'score_percent': 80, 'maturity_level': 'Managed'}],
                'next_steps_json': {'dependencies': [], 'next_30_days': [], 'next_60_days': [], 'next_90_days': []},
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            },
            'roadmap': {
                'plan': {
                    'id': self.plan.id,
                    'tenant_id': self.tenant_a.id,
                    'tenant_name': self.tenant_a.name,
                    'session_id': self.session_a.id,
                    'title': 'Rust Roadmap',
                    'summary': 'Roadmap summary',
                    'overall_priority': 'HIGH',
                    'planned_start': '2026-05-01',
                    'phase_count': 1,
                    'task_count': 1,
                    'open_task_count': 1,
                    'created_at': '2026-04-18T10:00:00Z',
                    'updated_at': '2026-04-18T11:00:00Z',
                },
                'phases': [{
                    'id': 50,
                    'plan_id': self.plan.id,
                    'name': 'Governance Phase',
                    'sort_order': 1,
                    'objective': 'Create governance.',
                    'duration_weeks': 2,
                    'planned_start': '2026-05-01',
                    'planned_end': '2026-05-14',
                    'task_count': 1,
                    'created_at': '2026-04-18T10:00:00Z',
                    'updated_at': '2026-04-18T11:00:00Z',
                }],
                'tasks': [{
                    'id': 51,
                    'phase_id': 50,
                    'phase_name': 'Governance Phase',
                    'measure_id': None,
                    'title': 'Policy aktualisieren',
                    'description': 'Update security policy',
                    'priority': 'HIGH',
                    'owner_role': 'CISO',
                    'due_in_days': 14,
                    'dependency_text': '',
                    'status': 'OPEN',
                    'status_label': 'Offen',
                    'planned_start': '2026-05-01',
                    'due_date': '2026-05-07',
                    'notes': '',
                    'incoming_dependency_count': 0,
                    'created_at': '2026-04-18T10:00:00Z',
                    'updated_at': '2026-04-18T11:00:00Z',
                }],
                'dependencies': [],
            },
            'domain_scores': [{
                'id': 10,
                'session_id': self.session_a.id,
                'domain_id': self.domain.id,
                'domain_code': 'GOV',
                'domain_name': 'Governance',
                'domain_sort_order': 1,
                'score_raw': 8,
                'score_percent': 80,
                'maturity_level': 'Managed',
                'gap_level': 'LOW',
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            }],
            'gaps': [{
                'id': 20,
                'session_id': self.session_a.id,
                'domain_id': self.domain.id,
                'domain_code': 'GOV',
                'domain_name': 'Governance',
                'question_id': None,
                'severity': 'HIGH',
                'severity_label': 'Hoch',
                'title': 'MFA-Abdeckung fehlt',
                'description': 'MFA is not consistently enforced.',
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            }],
            'measures': [{
                'id': 30,
                'session_id': self.session_a.id,
                'domain_id': self.domain.id,
                'domain_code': 'GOV',
                'domain_name': 'Governance',
                'question_id': None,
                'title': 'MFA ausrollen',
                'description': 'Roll out MFA.',
                'priority': 'CRITICAL',
                'priority_label': 'Kritisch',
                'effort': 'MEDIUM',
                'effort_label': 'Mittel',
                'measure_type': 'TECHNICAL',
                'measure_type_label': 'Technisch',
                'target_phase': '30 Tage',
                'owner_role': 'IAM Lead',
                'reason': 'Identity gap',
                'status': 'OPEN',
                'status_label': 'Offen',
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            }],
            'evidence_count': 2,
        }
