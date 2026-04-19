import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.assets_app.models import InformationAsset
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.risks.models import Risk, RiskCategory


User = get_user_model()


@override_settings(RISK_REGISTER_BACKEND='local', RUST_BACKEND_URL='')
class RiskViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-user',
            email='risk-user@example.test',
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
        self.category = RiskCategory.objects.create(tenant=self.tenant_a, name='Cyber Risk')
        self.process = Process.objects.create(tenant=self.tenant_a, name='Incident Intake')
        self.asset = InformationAsset.objects.create(tenant=self.tenant_a, name='Customer Portal')
        self.risk_a = Risk.objects.create(
            tenant=self.tenant_a,
            category=self.category,
            process=self.process,
            asset=self.asset,
            owner=self.user_a,
            title='Credential Phishing',
            description='Credential theft can disrupt SOC operations',
            threat='Phishing campaign',
            vulnerability='Weak MFA coverage',
            impact=5,
            likelihood=4,
            residual_impact=3,
            residual_likelihood=2,
            status=Risk.Status.TREATING,
            treatment_strategy=Risk.Treatment.MITIGATE,
            treatment_plan='Roll out phishing-resistant MFA',
        )
        self.risk_b = Risk.objects.create(
            tenant=self.tenant_b,
            owner=self.user_b,
            title='Foreign Risk',
            description='Foreign tenant risk',
            impact=5,
            likelihood=5,
        )

    def test_risk_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('risks:list'))

        self.assertEqual(response.status_code, 200)
        risks = list(response.context['risks'])
        self.assertEqual(risks, [self.risk_a])
        self.assertEqual(response.context['risk_register_source'], 'django')
        self.assertEqual(response.context['summary']['critical'], 1)
        self.assertContains(response, 'Credential Phishing')
        self.assertNotContains(response, 'Foreign Risk')

    @patch('apps.risks.services.urlopen')
    def test_risk_list_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'risks': [
                self._rust_risk_payload(title='Rust Credential Phishing'),
            ],
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(RISK_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('risks:list'))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/risks')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-email'), 'risk-user@example.test')
        risks = list(response.context['risks'])
        self.assertEqual(response.context['risk_register_source'], 'rust_service')
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0].title, 'Rust Credential Phishing')
        self.assertEqual(risks[0].tenant.name, 'Tenant A')
        self.assertEqual(risks[0].get_status_display(), 'In Behandlung')
        self.assertEqual(response.context['summary']['critical'], 1)
        self.assertContains(response, 'Rust Credential Phishing')
        self.assertContains(response, 'Ada Lovelace')

    @patch('apps.risks.services.urlopen')
    def test_risk_detail_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'risk': self._rust_risk_payload(description='Rust detail risk'),
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(RISK_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(reverse('risks:detail', args=[self.risk_a.pk]))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, f'http://rust-backend:9000/api/v1/risks/{self.risk_a.pk}')
        risk = response.context['risk']
        self.assertEqual(response.context['risk_register_source'], 'rust_service')
        self.assertEqual(risk.description, 'Rust detail risk')
        self.assertEqual(risk.owner.name, 'Ada Lovelace')
        self.assertEqual(risk.score, 20)
        self.assertEqual(risk.residual_score, 6)
        self.assertContains(response, 'Rust detail risk')
        self.assertContains(response, 'Customer Portal')

    @patch('apps.risks.services.urlopen')
    def test_risk_create_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'risk': self._rust_risk_payload(id=99, title='Rust Created Risk'),
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(RISK_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.post(reverse('risks:create'), data={
                'title': 'Rust Created Risk',
                'description': 'Created through Rust',
                'category': self.category.pk,
                'process': self.process.pk,
                'asset': self.asset.pk,
                'owner': self.user_a.pk,
                'threat': 'Credential stuffing',
                'vulnerability': 'Weak lockout',
                'impact': 4,
                'likelihood': 3,
                'residual_impact': 2,
                'residual_likelihood': 2,
                'status': Risk.Status.ANALYZING,
                'treatment_strategy': Risk.Treatment.MITIGATE,
                'treatment_plan': 'Harden login controls',
                'treatment_due_date': '2026-06-01',
                'review_date': '2026-06-15',
            })

        self.assertEqual(response.status_code, 302)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/risks')
        self.assertEqual(rust_request.get_method(), 'POST')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        payload = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(payload['title'], 'Rust Created Risk')
        self.assertEqual(payload['category_id'], self.category.pk)
        self.assertEqual(payload['process_id'], self.process.pk)
        self.assertEqual(payload['asset_id'], self.asset.pk)
        self.assertEqual(payload['owner_id'], self.user_a.pk)
        self.assertEqual(payload['impact'], 4)
        self.assertFalse(Risk.objects.filter(title='Rust Created Risk').exists())

    @patch('apps.risks.services.urlopen')
    def test_risk_update_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'risk': self._rust_risk_payload(title='Rust Updated Risk', status='CLOSED', status_label='Geschlossen'),
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(RISK_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.post(reverse('risks:edit', args=[self.risk_a.pk]), data={
                'title': 'Rust Updated Risk',
                'description': self.risk_a.description,
                'category': '',
                'process': '',
                'asset': '',
                'owner': '',
                'threat': self.risk_a.threat,
                'vulnerability': self.risk_a.vulnerability,
                'impact': 2,
                'likelihood': 4,
                'residual_impact': '',
                'residual_likelihood': '',
                'status': Risk.Status.CLOSED,
                'treatment_strategy': '',
                'treatment_plan': '',
                'treatment_due_date': '',
                'review_date': '',
            })

        self.assertEqual(response.status_code, 302)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, f'http://rust-backend:9000/api/v1/risks/{self.risk_a.pk}')
        self.assertEqual(rust_request.get_method(), 'PATCH')
        payload = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(payload['title'], 'Rust Updated Risk')
        self.assertIsNone(payload['category_id'])
        self.assertIsNone(payload['process_id'])
        self.assertIsNone(payload['asset_id'])
        self.assertIsNone(payload['owner_id'])
        self.assertEqual(payload['status'], Risk.Status.CLOSED)
        self.assertEqual(Risk.objects.get(pk=self.risk_a.pk).title, 'Credential Phishing')

    @patch('apps.risks.services.urlopen', side_effect=OSError('backend down'))
    def test_risk_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            RISK_REGISTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('risks:list'))

        self.assertEqual(response.status_code, 200)
        risks = list(response.context['risks'])
        self.assertEqual(response.context['risk_register_source'], 'django')
        self.assertEqual(risks, [self.risk_a])

    def test_risk_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(RISK_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('risks:list'))

    def _rust_risk_payload(self, **overrides):
        payload = {
            'id': self.risk_a.id,
            'tenant_id': self.tenant_a.id,
            'category_id': self.category.id,
            'category_name': 'Cyber Risk',
            'process_id': self.process.id,
            'process_name': 'Incident Intake',
            'asset_id': self.asset.id,
            'asset_name': 'Customer Portal',
            'owner_id': self.user_a.id,
            'owner_display': 'Ada Lovelace',
            'title': 'Credential Phishing',
            'description': 'Credential theft can disrupt SOC operations',
            'threat': 'Phishing campaign',
            'vulnerability': 'Weak MFA coverage',
            'impact': 5,
            'impact_label': '5 – Kritisch',
            'likelihood': 4,
            'likelihood_label': '4 – Wahrscheinlich',
            'residual_impact': 3,
            'residual_impact_label': '3 – Mittel',
            'residual_likelihood': 2,
            'residual_likelihood_label': '2 – Selten',
            'status': 'TREATING',
            'status_label': 'In Behandlung',
            'treatment_strategy': 'MITIGATE',
            'treatment_strategy_label': 'Mindern',
            'treatment_plan': 'Roll out phishing-resistant MFA',
            'treatment_due_date': '2026-04-30',
            'accepted_by_id': None,
            'accepted_by_display': None,
            'accepted_at': None,
            'review_date': '2026-05-01',
            'score': 20,
            'residual_score': 6,
            'risk_level': 'CRITICAL',
            'risk_level_label': 'Kritisch',
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload
