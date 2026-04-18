import json
from datetime import date
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.roadmap.models import RoadmapPhase, RoadmapPlan, RoadmapTask, RoadmapTaskDependency
from apps.wizard.models import AssessmentSession


User = get_user_model()


@override_settings(ROADMAP_REGISTER_BACKEND='local', RUST_BACKEND_URL='')
class RoadmapViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-roadmap',
            email='roadmap-user@example.test',
            password='testpass123',
            tenant=self.tenant_a,
            first_name='Ada',
            last_name='Lovelace',
        )
        self.user_b = User.objects.create_user(
            username='tenant-b-roadmap',
            password='testpass123',
            tenant=self.tenant_b,
        )
        self.session_a = AssessmentSession.objects.create(
            tenant=self.tenant_a,
            started_by=self.user_a,
            assessment_type=AssessmentSession.Type.FULL,
            status=AssessmentSession.Status.COMPLETED,
        )
        self.session_b = AssessmentSession.objects.create(
            tenant=self.tenant_b,
            started_by=self.user_b,
            assessment_type=AssessmentSession.Type.FULL,
        )
        self.plan_a = RoadmapPlan.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            title='Security Roadmap',
            summary='Bring controls to audit readiness.',
            overall_priority='HIGH',
            planned_start=date(2026, 5, 1),
        )
        self.phase_a = RoadmapPhase.objects.create(
            plan=self.plan_a,
            name='Governance',
            sort_order=1,
            objective='Create ownership and policies.',
            duration_weeks=2,
            planned_start=date(2026, 5, 1),
            planned_end=date(2026, 5, 14),
        )
        self.task_a = RoadmapTask.objects.create(
            phase=self.phase_a,
            title='Policy aktualisieren',
            description='Update security policy.',
            priority='HIGH',
            owner_role='CISO',
            status=RoadmapTask.Status.OPEN,
            planned_start=date(2026, 5, 1),
            due_date=date(2026, 5, 7),
        )
        self.task_b = RoadmapTask.objects.create(
            phase=self.phase_a,
            title='MFA ausrollen',
            description='Roll out MFA.',
            priority='CRITICAL',
            owner_role='IAM Lead',
            status=RoadmapTask.Status.IN_PROGRESS,
            planned_start=date(2026, 5, 8),
            due_date=date(2026, 5, 14),
        )
        RoadmapTaskDependency.objects.create(
            predecessor=self.task_a,
            successor=self.task_b,
            dependency_type=RoadmapTaskDependency.DependencyType.FINISH_TO_START,
            rationale='Policy gates rollout.',
        )
        self.plan_b = RoadmapPlan.objects.create(
            tenant=self.tenant_b,
            session=self.session_b,
            title='Foreign Roadmap',
            summary='Foreign tenant plan.',
        )

    def test_roadmap_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('roadmap:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['plans']), [self.plan_a])
        self.assertEqual(response.context['roadmap_register_source'], 'django')
        self.assertContains(response, 'Security Roadmap')
        self.assertNotContains(response, 'Foreign Roadmap')

    @patch('apps.roadmap.services.urlopen')
    def test_roadmap_list_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, {
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'plans': [self._rust_plan_payload(title='Rust Roadmap')],
        })
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('roadmap:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/roadmap/plans')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(response.context['roadmap_register_source'], 'rust_service')
        self.assertEqual(list(response.context['plans'])[0].title, 'Rust Roadmap')
        self.assertContains(response, 'Rust Roadmap')

    @patch('apps.roadmap.services.urlopen')
    def test_roadmap_detail_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_detail_payload())
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('roadmap:detail', kwargs={'pk': self.plan_a.id}))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, f'http://rust-backend:9000/api/v1/roadmap/plans/{self.plan_a.id}')
        self.assertEqual(response.context['roadmap_register_source'], 'rust_service')
        self.assertEqual(response.context['plan'].title, 'Rust Security Roadmap')
        self.assertEqual(response.context['total_tasks'], 2)
        self.assertContains(response, 'Rust Security Roadmap')
        self.assertContains(response, 'Policy aktualisieren')

    @patch('apps.roadmap.services.urlopen')
    def test_roadmap_kanban_can_use_rust_register_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_detail_payload())
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('roadmap:kanban', kwargs={'pk': self.plan_a.id}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['roadmap_register_source'], 'rust_service')
        self.assertContains(response, 'Policy aktualisieren')
        self.assertContains(response, '1 Abhängigkeit')

    @patch('apps.roadmap.services.urlopen')
    def test_roadmap_task_update_can_use_rust_register_bridge(self, mock_urlopen):
        payload = self._rust_detail_payload()['tasks'][0]
        payload.update({
            'status': 'DONE',
            'status_label': 'Erledigt',
            'planned_start': '2026-05-02',
            'due_date': '2026-05-08',
            'owner_role': 'CISO Office',
            'notes': 'Closed in Rust',
        })
        self._mock_rust_response(mock_urlopen, {
            'api_version': 'v1',
            'plan_id': self.plan_a.id,
            'task': payload,
        })
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.post(
                reverse('roadmap:task-edit', kwargs={'pk': self.task_a.id}),
                {
                    'status': 'DONE',
                    'planned_start': '2026-05-02',
                    'due_date': '2026-05-08',
                    'owner_role': 'CISO Office',
                    'notes': 'Closed in Rust',
                },
            )

        self.assertRedirects(
            response,
            reverse('roadmap:detail', kwargs={'pk': self.plan_a.id}),
            fetch_redirect_response=False,
        )
        rust_request = mock_urlopen.call_args.args[0]
        body = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(rust_request.full_url, f'http://rust-backend:9000/api/v1/roadmap/tasks/{self.task_a.id}')
        self.assertEqual(rust_request.get_method(), 'PATCH')
        self.assertEqual(body['status'], 'DONE')
        self.assertEqual(body['owner_role'], 'CISO Office')

    @patch('apps.roadmap.services.urlopen')
    def test_roadmap_pdf_can_use_rust_export_data(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_detail_payload())
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('roadmap:pdf', kwargs={'pk': self.plan_a.id}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, f'http://rust-backend:9000/api/v1/roadmap/plans/{self.plan_a.id}')

    @patch('apps.roadmap.services.urlopen', side_effect=OSError('backend down'))
    def test_roadmap_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            ROADMAP_REGISTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('roadmap:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['roadmap_register_source'], 'django')
        self.assertEqual(list(response.context['plans']), [self.plan_a])

    def test_roadmap_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(ROADMAP_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('roadmap:list'))

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx

    def _rust_plan_payload(self, **overrides):
        payload = {
            'id': self.plan_a.id,
            'tenant_id': self.tenant_a.id,
            'tenant_name': 'Tenant A',
            'session_id': self.session_a.id,
            'title': 'Security Roadmap',
            'summary': 'Bring controls to audit readiness.',
            'overall_priority': 'HIGH',
            'planned_start': '2026-05-01',
            'phase_count': 1,
            'task_count': 2,
            'open_task_count': 2,
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload

    def _rust_detail_payload(self):
        return {
            'api_version': 'v1',
            'plan': self._rust_plan_payload(title='Rust Security Roadmap'),
            'phases': [{
                'id': self.phase_a.id,
                'plan_id': self.plan_a.id,
                'name': 'Governance',
                'sort_order': 1,
                'objective': 'Create ownership and policies.',
                'duration_weeks': 2,
                'planned_start': '2026-05-01',
                'planned_end': '2026-05-14',
                'task_count': 2,
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            }],
            'tasks': [
                {
                    'id': self.task_a.id,
                    'phase_id': self.phase_a.id,
                    'phase_name': 'Governance',
                    'measure_id': None,
                    'title': 'Policy aktualisieren',
                    'description': 'Update security policy.',
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
                },
                {
                    'id': self.task_b.id,
                    'phase_id': self.phase_a.id,
                    'phase_name': 'Governance',
                    'measure_id': None,
                    'title': 'MFA ausrollen',
                    'description': 'Roll out MFA.',
                    'priority': 'CRITICAL',
                    'owner_role': 'IAM Lead',
                    'due_in_days': 21,
                    'dependency_text': 'Policy first',
                    'status': 'IN_PROGRESS',
                    'status_label': 'In Umsetzung',
                    'planned_start': '2026-05-08',
                    'due_date': '2026-05-14',
                    'notes': 'Pilot started',
                    'incoming_dependency_count': 1,
                    'created_at': '2026-04-18T10:00:00Z',
                    'updated_at': '2026-04-18T11:00:00Z',
                },
            ],
            'dependencies': [{
                'id': 5001,
                'predecessor_id': self.task_a.id,
                'predecessor_title': 'Policy aktualisieren',
                'successor_id': self.task_b.id,
                'successor_title': 'MFA ausrollen',
                'dependency_type': 'FS',
                'dependency_type_label': 'Finish-to-Start',
                'rationale': 'Policy gates rollout.',
                'created_at': '2026-04-18T10:00:00Z',
                'updated_at': '2026-04-18T11:00:00Z',
            }],
        }
