import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from apps.assets_app.models import InformationAsset
from apps.dashboard.services import DashboardRustClient, DashboardSummaryBridge
from apps.dashboard.views import DashboardDataMixin
from apps.evidence.models import EvidenceItem
from apps.organizations.models import Tenant
from apps.processes.models import Process
from apps.risks.models import Risk


class DashboardRustBridgeTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(
            name='Tenant SOC',
            slug='tenant-soc',
            country='DE',
            description='Tenant fuer Dashboard-Rust-Bridge-Test',
            sector='MSSP',
        )
        self.user = get_user_model().objects.create_user(
            username='dashboard-user',
            email='dashboard@example.test',
            password='secret',
            tenant=self.tenant,
        )
        self.request = RequestFactory().get('/dashboard/')
        self.request.user = self.user

    @patch('apps.dashboard.services.urlopen')
    def test_dashboard_rust_client_fetches_summary_with_tenant_headers(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant.id,
            'process_count': 2,
            'asset_count': 3,
            'open_risk_count': 4,
            'evidence_count': 5,
            'open_task_count': 6,
            'latest_report': {'id': 11, 'title': 'April Readiness'},
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx

        with self.settings(RUST_BACKEND_URL='http://rust-backend:9000'):
            summary = DashboardRustClient.fetch_summary(self.request, self.tenant)

        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, 'http://rust-backend:9000/api/v1/dashboard/summary')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user.id))
        self.assertEqual(summary['process_count'], 2)
        self.assertEqual(summary['latest_report']['id'], 11)

    def test_dashboard_bridge_raises_in_strict_mode_without_backend_url(self):
        with self.settings(RUST_BACKEND_URL='', DASHBOARD_SUMMARY_BACKEND='rust_service', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                DashboardSummaryBridge.fetch(self.request, self.tenant)

    def test_dashboard_bridge_is_disabled_for_local_backend(self):
        with self.settings(RUST_BACKEND_URL='', DASHBOARD_SUMMARY_BACKEND='local', RUST_STRICT_MODE=True):
            self.assertIsNone(DashboardSummaryBridge.fetch(self.request, self.tenant))

    @patch('apps.dashboard.views.DashboardSummaryBridge.fetch')
    def test_dashboard_context_uses_rust_summary_counts_when_available(self, mock_fetch):
        mock_fetch.return_value = {
            'process_count': 10,
            'asset_count': 11,
            'open_risk_count': 12,
            'evidence_count': 13,
            'open_task_count': 14,
        }

        context = DashboardDataMixin().build_dashboard_context(self.request)

        self.assertEqual(context['dashboard_summary_source'], 'rust_service')
        self.assertEqual(context['process_count'], 10)
        self.assertEqual(context['asset_count'], 11)
        self.assertEqual(context['open_risk_count'], 12)
        self.assertEqual(context['evidence_count'], 13)
        self.assertEqual(context['open_task_count'], 14)

    def test_dashboard_context_falls_back_to_django_counts_for_local_backend(self):
        Process.objects.create(tenant=self.tenant, name='Incident Intake')
        InformationAsset.objects.create(tenant=self.tenant, name='SIEM')
        Risk.objects.create(
            tenant=self.tenant,
            title='Credential Phishing',
            description='Phishing kann Account Compromise ausloesen.',
        )
        EvidenceItem.objects.create(tenant=self.tenant, title='SOC Playbook')

        with self.settings(DASHBOARD_SUMMARY_BACKEND='local', RUST_BACKEND_URL=''):
            context = DashboardDataMixin().build_dashboard_context(self.request)

        self.assertEqual(context['dashboard_summary_source'], 'django')
        self.assertEqual(context['process_count'], 1)
        self.assertEqual(context['asset_count'], 1)
        self.assertEqual(context['open_risk_count'], 1)
        self.assertEqual(context['evidence_count'], 1)
