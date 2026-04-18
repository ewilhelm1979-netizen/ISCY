import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import BusinessUnit, Tenant
from apps.processes.models import Process


User = get_user_model()


@override_settings(PROCESS_REGISTER_BACKEND='local', RUST_BACKEND_URL='')
class ProcessViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-user',
            email='process-user@example.test',
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
        self.business_unit = BusinessUnit.objects.create(tenant=self.tenant_a, name='Security Operations')
        self.process_a = Process.objects.create(
            tenant=self.tenant_a,
            business_unit=self.business_unit,
            owner=self.user_a,
            name='Incident Intake',
            scope='SOC',
            description='SOC intake process',
            status=Process.Status.PARTIAL,
            documented=True,
            approved=True,
            communicated=True,
            implemented=True,
        )
        self.process_b = Process.objects.create(
            tenant=self.tenant_b,
            owner=self.user_b,
            name='Foreign Process',
            status=Process.Status.SUFFICIENT,
        )

    def test_process_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('processes:list'))

        self.assertEqual(response.status_code, 200)
        processes = list(response.context['processes'])
        self.assertEqual(processes, [self.process_a])
        self.assertEqual(response.context['process_register_source'], 'django')
        self.assertContains(response, 'Incident Intake')
        self.assertNotContains(response, 'Foreign Process')

    @patch('apps.processes.services.urlopen')
    def test_process_list_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'processes': [
                self._rust_process_payload(name='Rust Incident Intake'),
            ],
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(PROCESS_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('processes:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/processes')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-email'), 'process-user@example.test')
        processes = list(response.context['processes'])
        self.assertEqual(response.context['process_register_source'], 'rust_service')
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].name, 'Rust Incident Intake')
        self.assertEqual(processes[0].tenant.name, 'Tenant A')
        self.assertEqual(processes[0].get_status_display(), 'Vorhanden, aber unvollständig')
        self.assertContains(response, 'Rust Incident Intake')
        self.assertContains(response, 'Ada Lovelace')

    @patch('apps.processes.services.urlopen')
    def test_process_detail_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'process': self._rust_process_payload(description='Rust detail process'),
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(PROCESS_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('processes:detail', args=[self.process_a.pk]))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f'http://rust-backend:9000/api/v1/processes/{self.process_a.pk}',
        )
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        process = response.context['process']
        self.assertEqual(response.context['process_register_source'], 'rust_service')
        self.assertEqual(process.description, 'Rust detail process')
        self.assertEqual(process.owner.name, 'Ada Lovelace')
        self.assertContains(response, 'Rust detail process')
        self.assertContains(response, 'Operativ wirksam')

    @patch('apps.processes.services.urlopen', side_effect=OSError('backend down'))
    def test_process_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            PROCESS_REGISTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('processes:list'))

        self.assertEqual(response.status_code, 200)
        processes = list(response.context['processes'])
        self.assertEqual(response.context['process_register_source'], 'django')
        self.assertEqual(processes, [self.process_a])

    def test_process_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(PROCESS_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('processes:list'))

    def _rust_process_payload(self, **overrides):
        payload = {
            'id': self.process_a.id,
            'tenant_id': self.tenant_a.id,
            'business_unit_id': self.business_unit.id,
            'business_unit_name': 'Security Operations',
            'owner_id': self.user_a.id,
            'owner_display': 'Ada Lovelace',
            'name': 'Incident Intake',
            'scope': 'SOC',
            'description': 'SOC intake process',
            'status': 'PARTIAL',
            'status_label': 'Vorhanden, aber unvollständig',
            'documented': True,
            'approved': True,
            'communicated': True,
            'implemented': True,
            'effective': False,
            'evidenced': False,
            'reviewed_at': '2026-04-18',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload
