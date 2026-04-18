import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.assessments.models import ApplicabilityAssessment, Assessment, Measure
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.requirements_app.models import Requirement


User = get_user_model()


@override_settings(ASSESSMENT_REGISTER_BACKEND='local', RUST_BACKEND_URL='')
class AssessmentViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-user',
            email='assessment-user@example.test',
            password='testpass123',
            tenant=self.tenant_a,
            first_name='Ada',
            last_name='Lovelace',
        )
        self.user_b = User.objects.create_user(
            username='tenant-b-user',
            password='testpass123',
            tenant=self.tenant_b,
        )
        self.process_a = Process.objects.create(
            tenant=self.tenant_a,
            owner=self.user_a,
            name='Incident Intake',
            status=Process.Status.PARTIAL,
        )
        self.process_b = Process.objects.create(
            tenant=self.tenant_b,
            owner=self.user_b,
            name='Foreign Process',
            status=Process.Status.SUFFICIENT,
        )
        self.requirement = Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.17',
            title='Authentication Information',
            domain='IAM',
            description='Protect authentication information.',
        )
        self.applicability_a = ApplicabilityAssessment.objects.create(
            tenant=self.tenant_a,
            sector='MSSP',
            company_size='medium',
            critical_services='Managed detection and response',
            supply_chain_role='critical supplier',
            status=ApplicabilityAssessment.Status.RELEVANT,
            reasoning='Digital provider with critical customer services',
        )
        self.applicability_b = ApplicabilityAssessment.objects.create(
            tenant=self.tenant_b,
            sector='Retail',
            status=ApplicabilityAssessment.Status.NOT_DIRECTLY_RELEVANT,
            reasoning='Foreign tenant',
        )
        self.assessment_a = Assessment.objects.create(
            tenant=self.tenant_a,
            process=self.process_a,
            requirement=self.requirement,
            owner=self.user_a,
            status=Assessment.Status.PARTIAL,
            score=3,
            notes='MFA rollout started',
        )
        self.assessment_b = Assessment.objects.create(
            tenant=self.tenant_b,
            process=self.process_b,
            requirement=self.requirement,
            owner=self.user_b,
            status=Assessment.Status.FULFILLED,
            score=5,
        )
        self.measure_a = Measure.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment_a,
            owner=self.user_a,
            title='MFA ausrollen',
            priority=Measure.Priority.HIGH,
            status=Measure.Status.OPEN,
            due_date='2026-05-01',
        )
        self.measure_b = Measure.objects.create(
            tenant=self.tenant_b,
            assessment=self.assessment_b,
            owner=self.user_b,
            title='Foreign Measure',
            priority=Measure.Priority.LOW,
            status=Measure.Status.OPEN,
        )

    def test_assessment_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('assessments:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['items']), [self.assessment_a])
        self.assertEqual(response.context['assessment_register_source'], 'django')
        self.assertContains(response, 'Incident Intake')
        self.assertNotContains(response, 'Foreign Process')

    @patch('apps.assessments.services.urlopen')
    def test_applicability_list_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, [self._rust_applicability_payload(sector='Rust MSSP')])
        self.client.force_login(self.user_a)

        with self.settings(ASSESSMENT_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('assessments:applicability_list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/assessments/applicability')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(response.context['assessment_register_source'], 'rust_service')
        self.assertEqual(list(response.context['items'])[0].sector, 'Rust MSSP')
        self.assertContains(response, 'Rust MSSP')
        self.assertContains(response, 'Voraussichtlich relevant')

    @patch('apps.assessments.services.urlopen')
    def test_assessment_list_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, [self._rust_assessment_payload()])
        self.client.force_login(self.user_a)

        with self.settings(ASSESSMENT_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('assessments:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/assessments')
        items = list(response.context['items'])
        self.assertEqual(response.context['assessment_register_source'], 'rust_service')
        self.assertEqual(items[0].process.name, 'Incident Intake')
        self.assertEqual(str(items[0].requirement), 'ISO27001 - A.5.17')
        self.assertEqual(items[0].get_status_display(), 'Teilweise erfüllt')
        self.assertContains(response, 'Incident Intake')
        self.assertContains(response, 'Teilweise erfüllt')

    @patch('apps.assessments.services.urlopen')
    def test_measure_list_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, [self._rust_measure_payload(title='Rust MFA ausrollen')])
        self.client.force_login(self.user_a)

        with self.settings(ASSESSMENT_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('assessments:measure_list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/assessments/measures')
        items = list(response.context['items'])
        self.assertEqual(response.context['assessment_register_source'], 'rust_service')
        self.assertEqual(items[0].title, 'Rust MFA ausrollen')
        self.assertEqual(items[0].get_priority_display(), 'High')
        self.assertEqual(items[0].get_status_display(), 'Open')
        self.assertContains(response, 'Rust MFA ausrollen')
        self.assertContains(response, 'High')

    @patch('apps.assessments.services.urlopen', side_effect=OSError('backend down'))
    def test_assessment_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            ASSESSMENT_REGISTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('assessments:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['assessment_register_source'], 'django')
        self.assertEqual(list(response.context['items']), [self.assessment_a])

    def test_assessment_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(ASSESSMENT_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('assessments:list'))

    def _mock_rust_response(self, mock_urlopen, items):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'items': items,
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx

    def _rust_applicability_payload(self, **overrides):
        payload = {
            'id': self.applicability_a.id,
            'tenant_id': self.tenant_a.id,
            'tenant_name': 'Tenant A',
            'sector': 'MSSP',
            'company_size': 'medium',
            'critical_services': 'Managed detection and response',
            'supply_chain_role': 'critical supplier',
            'status': 'RELEVANT',
            'status_label': 'Voraussichtlich relevant',
            'reasoning': 'Digital provider with critical customer services',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload

    def _rust_assessment_payload(self, **overrides):
        payload = {
            'id': self.assessment_a.id,
            'tenant_id': self.tenant_a.id,
            'process_id': self.process_a.id,
            'process_name': 'Incident Intake',
            'requirement_id': self.requirement.id,
            'requirement_framework': 'ISO27001',
            'requirement_code': 'A.5.17',
            'requirement_title': 'Authentication Information',
            'owner_id': self.user_a.id,
            'owner_display': 'Ada Lovelace',
            'status': 'PARTIAL',
            'status_label': 'Teilweise erfüllt',
            'score': 3,
            'notes': 'MFA rollout started',
            'evidence_summary': 'Screenshots available',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload

    def _rust_measure_payload(self, **overrides):
        payload = {
            'id': self.measure_a.id,
            'tenant_id': self.tenant_a.id,
            'assessment_id': self.assessment_a.id,
            'assessment_display': 'Incident Intake -> ISO27001 - A.5.17',
            'owner_id': self.user_a.id,
            'owner_display': 'Ada Lovelace',
            'title': 'MFA ausrollen',
            'description': 'Roll out phishing-resistant MFA',
            'priority': 'HIGH',
            'priority_label': 'High',
            'status': 'OPEN',
            'status_label': 'Open',
            'due_date': '2026-05-01',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload
