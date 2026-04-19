import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant

from .models import MappingVersion, RegulatorySource, Requirement


User = get_user_model()


@override_settings(REQUIREMENTS_BACKEND='local', RUST_BACKEND_URL='')
class RequirementViewTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.user = User.objects.create_user(
            username='requirements-user',
            email='requirements@example.test',
            password='testpass123',
            tenant=self.tenant,
        )
        self.version = MappingVersion.objects.create(
            framework=Requirement.Framework.ISO27001,
            slug='iso27001-2022',
            title='ISO 27001 Mapping',
            version='2022',
            program_name='ISCY',
            status=MappingVersion.Status.ACTIVE,
        )
        self.source = RegulatorySource.objects.create(
            framework=Requirement.Framework.ISO27001,
            mapping_version=self.version,
            code='A.5.17',
            title='Authentication Information',
            authority='ISO',
            source_type=RegulatorySource.SourceType.STANDARD,
        )
        self.requirement = Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.17',
            title='Authentication Information',
            domain='Identity',
            description='Protect authentication information',
            evidence_required=True,
            legal_reference='ISO/IEC 27001:2022 A.5.17',
            mapping_version=self.version,
            primary_source=self.source,
        )

    def test_requirement_view_uses_local_library_by_default(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('requirements:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['requirements_source'], 'django')
        self.assertContains(response, 'Authentication Information')
        self.assertContains(response, 'ISO27001')

    @patch('apps.requirements_app.services_rust.urlopen')
    def test_requirement_view_can_use_rust_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_payload())
        self.client.force_login(self.user)

        with self.settings(REQUIREMENTS_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('requirements:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/requirements')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant.id))
        self.assertEqual(response.context['requirements_source'], 'rust_service')
        self.assertContains(response, 'Rust Authentication')
        self.assertContains(response, 'ISO27001')
        self.assertEqual(response.context['mapping_versions']['ISO27001']['version'], '2022')

    @patch('apps.requirements_app.services_rust.urlopen', side_effect=OSError('backend down'))
    def test_requirement_view_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user)

        with self.settings(
            REQUIREMENTS_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('requirements:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['requirements_source'], 'django')
        self.assertContains(response, 'Authentication Information')

    def test_requirement_view_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user)

        with self.settings(REQUIREMENTS_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('requirements:list'))

    def _rust_payload(self):
        return {
            'api_version': 'v1',
            'mapping_versions': [{
                'id': self.version.id,
                'framework': 'ISO27001',
                'slug': 'iso27001-2022',
                'title': 'ISO 27001 Mapping',
                'version': '2022',
                'program_name': 'ISCY',
                'status': 'ACTIVE',
                'status_label': 'Aktiv',
                'effective_on': '2026-01-01',
                'notes': 'Active mapping',
                'source_count': 1,
                'requirement_count': 1,
                'created_at': '2026-04-19T10:00:00Z',
                'updated_at': '2026-04-19T11:00:00Z',
            }],
            'requirements': [{
                'id': self.requirement.id,
                'framework': 'ISO27001',
                'framework_label': 'ISO 27001',
                'code': 'A.5.17',
                'title': 'Rust Authentication',
                'domain': 'Identity',
                'description': 'Protect authentication information',
                'guidance': 'Use MFA',
                'is_active': True,
                'evidence_required': True,
                'evidence_guidance': 'MFA policy',
                'evidence_examples': 'Policy',
                'sector_package': 'ALL',
                'legal_reference': 'ISO/IEC 27001:2022 A.5.17',
                'coverage_level': 'PRIMARY',
                'coverage_level_label': 'Primaer',
                'mapping_version': {
                    'id': self.version.id,
                    'framework': 'ISO27001',
                    'slug': 'iso27001-2022',
                    'title': 'ISO 27001 Mapping',
                    'version': '2022',
                    'program_name': 'ISCY',
                    'status': 'ACTIVE',
                    'status_label': 'Aktiv',
                    'effective_on': '2026-01-01',
                    'notes': 'Active mapping',
                    'source_count': 1,
                    'requirement_count': 1,
                    'created_at': '2026-04-19T10:00:00Z',
                    'updated_at': '2026-04-19T11:00:00Z',
                },
                'primary_source': {
                    'id': self.source.id,
                    'framework': 'ISO27001',
                    'code': 'A.5.17',
                    'title': 'Authentication Information',
                    'authority': 'ISO',
                    'citation': '',
                    'url': '',
                    'source_type': 'STANDARD',
                },
                'created_at': '2026-04-19T10:00:00Z',
                'updated_at': '2026-04-19T11:00:00Z',
            }],
        }

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
