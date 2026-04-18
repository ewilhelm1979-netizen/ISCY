import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant

from .forms import DataImportForm
from .services import ImportCenterBridge


User = get_user_model()


@override_settings(IMPORT_CENTER_BACKEND='local', RUST_BACKEND_URL='')
class ImportCenterBridgeTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.user = User.objects.create_user(
            username='tenant-a-imports',
            email='import-user@example.test',
            password='testpass123',
            tenant=self.tenant,
        )
        self.factory = RequestFactory()

    @patch('apps.import_center.services.urlopen')
    def test_import_bridge_posts_rows_to_rust_backend(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, {
            'accepted': True,
            'api_version': 'v1',
            'result': {
                'tenant_id': self.tenant.id,
                'import_type': 'processes',
                'row_count': 1,
                'created': 1,
                'updated': 0,
                'skipped': 0,
            },
        })
        request = self.factory.post('/imports/preview/')
        request.user = self.user

        with self.settings(IMPORT_CENTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            result = ImportCenterBridge.apply_import(
                request,
                self.tenant,
                'processes',
                [{'name': 'Incident Intake', 'status': 'PARTIAL'}],
                replace_existing=False,
            )

        rust_request = mock_urlopen.call_args.args[0]
        body = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/import-center/jobs')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user.id))
        self.assertEqual(body['import_type'], 'processes')
        self.assertEqual(body['rows'][0]['name'], 'Incident Intake')
        self.assertEqual(result.created, 1)
        self.assertEqual(result.updated, 0)

    @patch('apps.import_center.services.urlopen', side_effect=OSError('backend down'))
    def test_import_bridge_falls_back_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        request = self.factory.post('/imports/preview/')
        request.user = self.user

        with self.settings(
            IMPORT_CENTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            result = ImportCenterBridge.apply_import(
                request,
                self.tenant,
                'business_units',
                [{'name': 'Security Operations'}],
            )

        self.assertIsNone(result)

    def test_import_bridge_raises_in_strict_mode_without_rust_backend_url(self):
        request = self.factory.post('/imports/preview/')
        request.user = self.user

        with self.settings(IMPORT_CENTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                ImportCenterBridge.apply_import(request, self.tenant, 'business_units', [{'name': 'Security'}])

    @patch('apps.import_center.services.urlopen')
    def test_preview_confirm_can_use_rust_import_backend(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, {
            'accepted': True,
            'api_version': 'v1',
            'result': {
                'tenant_id': self.tenant.id,
                'import_type': 'processes',
                'row_count': 1,
                'created': 1,
                'updated': 0,
                'skipped': 0,
            },
        })
        self.client.force_login(self.user)
        session = self.client.session
        session['import_preview'] = {
            'import_type': DataImportForm.ImportType.PROCESSES,
            'replace_existing': False,
            'headers': ['Name', 'Status'],
            'rows': [{'Name': 'Incident Intake', 'Status': 'PARTIAL'}],
            'mapping_rows': [],
            'selected_mapping': {'name': 'Name', 'status': 'Status'},
            'extra_headers': [],
            'matched': 2,
        }
        session.save()

        with self.settings(IMPORT_CENTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.post(
                reverse('imports:preview'),
                {
                    'action': 'confirm',
                    'map_name': 'Name',
                    'map_status': 'Status',
                },
            )

        self.assertRedirects(response, reverse('imports:center'))
        rust_request = mock_urlopen.call_args.args[0]
        body = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(body['import_type'], 'processes')
        self.assertEqual(body['rows'][0]['name'], 'Incident Intake')
        self.assertEqual(body['rows'][0]['status'], 'PARTIAL')

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
