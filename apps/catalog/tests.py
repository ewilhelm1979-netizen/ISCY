import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant

from .models import AssessmentDomain, AssessmentQuestion


User = get_user_model()


@override_settings(CATALOG_BACKEND='local', RUST_BACKEND_URL='')
class CatalogViewTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.user = User.objects.create_user(
            username='catalog-user',
            email='catalog@example.test',
            password='testpass123',
            tenant=self.tenant,
        )
        self.domain = AssessmentDomain.objects.create(
            code='GOV',
            name='Governance',
            description='Governance controls',
            sort_order=1,
        )
        AssessmentQuestion.objects.create(
            domain=self.domain,
            code='GOV-APP-1',
            text='Ist der Scope geklaert?',
            question_kind=AssessmentQuestion.Kind.APPLICABILITY,
            wizard_step=AssessmentQuestion.Step.APPLICABILITY,
            sort_order=1,
        )

    def test_catalog_view_uses_local_catalog_by_default(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('catalog:domains'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['catalog_source'], 'django')
        self.assertEqual(response.context['question_count'], 1)
        self.assertContains(response, 'Governance')

    @patch('apps.catalog.services.urlopen')
    def test_catalog_view_can_use_rust_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, {
            'api_version': 'v1',
            'question_count': 1,
            'domains': [{
                'id': self.domain.id,
                'code': 'GOV',
                'name': 'Rust Governance',
                'description': 'Rust catalog',
                'weight': 10,
                'sort_order': 1,
                'question_count': 1,
                'created_at': '2026-04-19T10:00:00Z',
                'updated_at': '2026-04-19T11:00:00Z',
                'questions': [{
                    'id': 10,
                    'domain_id': self.domain.id,
                    'code': 'GOV-RUST-1',
                    'text': 'Rust-Frage',
                    'help_text': '',
                    'why_it_matters': '',
                    'question_kind': 'MATURITY',
                    'question_kind_label': 'Reifegrad',
                    'wizard_step': 'maturity',
                    'wizard_step_label': 'Reifegrad',
                    'weight': 10,
                    'is_required': True,
                    'applies_to_iso27001': True,
                    'applies_to_nis2': True,
                    'applies_to_cra': False,
                    'applies_to_ai_act': False,
                    'applies_to_iec62443': False,
                    'applies_to_iso_sae_21434': False,
                    'applies_to_product_security': False,
                    'sort_order': 1,
                    'created_at': '2026-04-19T10:00:00Z',
                    'updated_at': '2026-04-19T11:00:00Z',
                }],
            }],
        })
        self.client.force_login(self.user)

        with self.settings(CATALOG_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('catalog:domains'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/catalog/domains')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant.id))
        self.assertEqual(response.context['catalog_source'], 'rust_service')
        self.assertEqual(response.context['question_count'], 1)
        self.assertContains(response, 'Rust Governance')
        self.assertContains(response, 'Rust-Frage')

    @patch('apps.catalog.services.urlopen', side_effect=OSError('backend down'))
    def test_catalog_view_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user)

        with self.settings(
            CATALOG_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('catalog:domains'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['catalog_source'], 'django')
        self.assertContains(response, 'Governance')

    def test_catalog_view_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user)

        with self.settings(CATALOG_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('catalog:domains'))

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
