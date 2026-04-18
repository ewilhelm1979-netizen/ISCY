import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.assets_app.models import InformationAsset
from apps.organizations.models import BusinessUnit, Tenant


User = get_user_model()


@override_settings(ASSET_INVENTORY_BACKEND='local', RUST_BACKEND_URL='')
class InformationAssetViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')

        self.user_a = User.objects.create_user(
            username='tenant-a-user',
            email='asset-user@example.test',
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
        self.business_unit = BusinessUnit.objects.create(tenant=self.tenant_a, name='Digital Services')
        self.asset_a = InformationAsset.objects.create(
            tenant=self.tenant_a,
            business_unit=self.business_unit,
            owner=self.user_a,
            name='Customer Portal',
            asset_type=InformationAsset.Type.APPLICATION,
            criticality=InformationAsset.Criticality.HIGH,
            description='External customer platform',
        )
        self.asset_b = InformationAsset.objects.create(
            tenant=self.tenant_b,
            owner=self.user_b,
            name='Foreign CRM',
            asset_type=InformationAsset.Type.SERVICE,
            criticality=InformationAsset.Criticality.LOW,
        )

    def test_asset_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('assets:list'))

        self.assertEqual(response.status_code, 200)
        assets = list(response.context['assets'])
        self.assertEqual(assets, [self.asset_a])
        self.assertEqual(response.context['asset_inventory_source'], 'django')
        self.assertContains(response, 'Customer Portal')
        self.assertNotContains(response, 'Foreign CRM')

    @patch('apps.assets_app.services.urlopen')
    def test_asset_list_can_use_rust_inventory_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'assets': [
                {
                    'id': self.asset_a.id,
                    'tenant_id': self.tenant_a.id,
                    'business_unit_id': self.business_unit.id,
                    'business_unit_name': 'Digital Services',
                    'owner_id': self.user_a.id,
                    'owner_display': 'Ada Lovelace',
                    'name': 'Rust Customer Portal',
                    'asset_type': 'APPLICATION',
                    'asset_type_label': 'Anwendung',
                    'criticality': 'HIGH',
                    'criticality_label': 'Hoch',
                    'description': 'External customer platform',
                    'confidentiality': 'HIGH',
                    'integrity': 'HIGH',
                    'availability': 'MEDIUM',
                    'lifecycle_status': 'active',
                    'is_in_scope': True,
                    'created_at': '2026-04-18T10:00:00Z',
                    'updated_at': '2026-04-18T11:00:00Z',
                }
            ],
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(ASSET_INVENTORY_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('assets:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/assets/information-assets')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-email'), 'asset-user@example.test')
        assets = list(response.context['assets'])
        self.assertEqual(response.context['asset_inventory_source'], 'rust_service')
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].name, 'Rust Customer Portal')
        self.assertEqual(assets[0].tenant.name, 'Tenant A')
        self.assertEqual(assets[0].get_asset_type_display(), 'Anwendung')
        self.assertEqual(assets[0].get_criticality_display(), 'Hoch')
        self.assertContains(response, 'Rust Customer Portal')
        self.assertContains(response, 'Ada Lovelace')

    @patch('apps.assets_app.services.urlopen', side_effect=OSError('backend down'))
    def test_asset_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            ASSET_INVENTORY_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('assets:list'))

        self.assertEqual(response.status_code, 200)
        assets = list(response.context['assets'])
        self.assertEqual(response.context['asset_inventory_source'], 'django')
        self.assertEqual(assets, [self.asset_a])

    def test_asset_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(ASSET_INVENTORY_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('assets:list'))
