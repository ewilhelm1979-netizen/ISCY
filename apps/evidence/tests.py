import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.evidence.models import EvidenceItem, RequirementEvidenceNeed
from apps.organizations.models import Tenant
from apps.requirements_app.models import MappingVersion, RegulatorySource, Requirement
from apps.wizard.models import AssessmentSession


User = get_user_model()


@override_settings(EVIDENCE_REGISTER_BACKEND='local', RUST_BACKEND_URL='')
class EvidenceViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name='Tenant A', slug='tenant-a', country='DE')
        self.tenant_b = Tenant.objects.create(name='Tenant B', slug='tenant-b', country='DE')
        self.user_a = User.objects.create_user(
            username='tenant-a-user',
            email='evidence-user@example.test',
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
        self.session_a = AssessmentSession.objects.create(tenant=self.tenant_a, started_by=self.user_a)
        self.session_b = AssessmentSession.objects.create(tenant=self.tenant_b, started_by=self.user_b)
        self.mapping_version = MappingVersion.objects.create(
            framework='ISO27001',
            slug='iso27001-2022',
            title='ISO 27001',
            version='2022',
            program_name='ISCY',
        )
        self.source = RegulatorySource.objects.create(
            framework='ISO27001',
            mapping_version=self.mapping_version,
            code='A.5.17',
            title='Authentication information',
            authority='ISO',
            citation='A.5.17',
        )
        self.requirement = Requirement.objects.create(
            framework=Requirement.Framework.ISO27001,
            code='A.5.17',
            title='Authentication Information',
            domain='IAM',
            description='Protect authentication information.',
            mapping_version=self.mapping_version,
            primary_source=self.source,
        )
        self.evidence_a = EvidenceItem.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            requirement=self.requirement,
            title='MFA Rollout Screenshot',
            description='Screenshot of enforced MFA policy',
            linked_requirement='ISO27001 A.5.17',
            status=EvidenceItem.Status.APPROVED,
            owner=self.user_a,
        )
        self.evidence_b = EvidenceItem.objects.create(
            tenant=self.tenant_b,
            session=self.session_b,
            requirement=self.requirement,
            title='Foreign Evidence',
            status=EvidenceItem.Status.DRAFT,
            owner=self.user_b,
        )
        self.need_a = RequirementEvidenceNeed.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            requirement=self.requirement,
            title='Nachweis für ISO27001 A.5.17',
            description='MFA policy evidence',
            status=RequirementEvidenceNeed.Status.COVERED,
            covered_count=1,
        )
        self.need_b = RequirementEvidenceNeed.objects.create(
            tenant=self.tenant_b,
            session=self.session_b,
            requirement=self.requirement,
            title='Foreign Need',
            status=RequirementEvidenceNeed.Status.OPEN,
        )

    def test_evidence_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse('evidence:list'))

        self.assertEqual(response.status_code, 200)
        evidence_items = list(response.context['evidence_items'])
        evidence_needs = list(response.context['evidence_needs'])
        self.assertEqual(evidence_items, [self.evidence_a])
        self.assertEqual(evidence_needs, [self.need_a])
        self.assertEqual(response.context['evidence_register_source'], 'django')
        self.assertEqual(response.context['need_summary']['covered'], 1)
        self.assertContains(response, 'MFA Rollout Screenshot')
        self.assertNotContains(response, 'Foreign Evidence')

    @patch('apps.evidence.services.urlopen')
    def test_evidence_list_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'api_version': 'v1',
            'tenant_id': self.tenant_a.id,
            'session_id': self.session_a.id,
            'evidence_items': [
                self._rust_evidence_payload(title='Rust MFA Evidence'),
            ],
            'evidence_needs': [
                self._rust_need_payload(title='Rust Evidence Need'),
            ],
            'need_summary': {'open': 0, 'partial': 0, 'covered': 1},
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(EVIDENCE_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.get(f"{reverse('evidence:list')}?session={self.session_a.id}")

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f'http://rust-backend:9000/api/v1/evidence?session_id={self.session_a.id}',
        )
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-email'), 'evidence-user@example.test')
        evidence_items = list(response.context['evidence_items'])
        evidence_needs = list(response.context['evidence_needs'])
        self.assertEqual(response.context['evidence_register_source'], 'rust_service')
        self.assertEqual(evidence_items[0].title, 'Rust MFA Evidence')
        self.assertEqual(evidence_items[0].tenant.name, 'Tenant A')
        self.assertEqual(evidence_items[0].get_status_display(), 'Freigegeben')
        self.assertEqual(evidence_items[0].owner.name, 'Ada Lovelace')
        self.assertEqual(evidence_needs[0].requirement_mapping_version, 'ISCY ISO27001 v2022')
        self.assertEqual(response.context['need_summary']['covered'], 1)
        self.assertContains(response, 'Rust MFA Evidence')
        self.assertContains(response, 'ISO27001 A.5.17')
        self.assertContains(response, 'Abgedeckt')

    @patch('apps.evidence.services.urlopen')
    def test_evidence_need_sync_can_use_rust_register_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            'accepted': True,
            'api_version': 'v1',
            'session_id': self.session_a.id,
            'created': 1,
            'updated': 2,
            'need_summary': {'open': 1, 'partial': 1, 'covered': 0},
        }).encode('utf-8')
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(EVIDENCE_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='http://rust-backend:9000'):
            response = self.client.post(reverse('evidence:sync-needs', args=[self.session_a.pk]))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], f"{reverse('evidence:list')}?session={self.session_a.id}")
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f'http://rust-backend:9000/api/v1/evidence/sessions/{self.session_a.id}/needs/sync',
        )
        self.assertEqual(rust_request.get_method(), 'POST')
        self.assertEqual(rust_request.get_header('X-iscy-tenant-id'), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header('X-iscy-user-id'), str(self.user_a.id))
        payload = json.loads(rust_request.data.decode('utf-8'))
        self.assertEqual(payload['covered_threshold'], 2)
        self.assertEqual(payload['partial_threshold'], 1)

    @patch('apps.evidence.services.urlopen', side_effect=OSError('backend down'))
    def test_evidence_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            EVIDENCE_REGISTER_BACKEND='rust_service',
            RUST_BACKEND_URL='http://rust-backend:9000',
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse('evidence:list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['evidence_register_source'], 'django')
        self.assertEqual(list(response.context['evidence_items']), [self.evidence_a])

    def test_evidence_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(EVIDENCE_REGISTER_BACKEND='rust_service', RUST_BACKEND_URL='', RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse('evidence:list'))

    def _rust_evidence_payload(self, **overrides):
        payload = {
            'id': self.evidence_a.id,
            'tenant_id': self.tenant_a.id,
            'session_id': self.session_a.id,
            'domain_id': None,
            'measure_id': None,
            'measure_title': None,
            'requirement_id': self.requirement.id,
            'requirement_framework': 'ISO27001',
            'requirement_code': 'A.5.17',
            'requirement_title': 'Authentication Information',
            'mapping_program_name': 'ISCY',
            'mapping_version': '2022',
            'source_authority': 'ISO',
            'source_citation': 'A.5.17',
            'source_title': 'Authentication information',
            'title': 'MFA Rollout Screenshot',
            'description': 'Screenshot of enforced MFA policy',
            'linked_requirement': 'ISO27001 A.5.17',
            'file_name': None,
            'status': 'APPROVED',
            'status_label': 'Freigegeben',
            'owner_id': self.user_a.id,
            'owner_display': 'Ada Lovelace',
            'review_notes': '',
            'reviewed_by_id': None,
            'reviewed_by_display': None,
            'reviewed_at': None,
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload

    def _rust_need_payload(self, **overrides):
        payload = {
            'id': self.need_a.id,
            'tenant_id': self.tenant_a.id,
            'session_id': self.session_a.id,
            'requirement_id': self.requirement.id,
            'requirement_framework': 'ISO27001',
            'requirement_code': 'A.5.17',
            'requirement_title': 'Authentication Information',
            'mapping_program_name': 'ISCY',
            'mapping_version': '2022',
            'source_authority': 'ISO',
            'source_citation': 'A.5.17',
            'source_title': 'Authentication information',
            'title': 'Nachweis für ISO27001 A.5.17',
            'description': 'MFA policy evidence',
            'is_mandatory': True,
            'status': 'COVERED',
            'status_label': 'Abgedeckt',
            'rationale': '',
            'covered_count': 1,
            'created_at': '2026-04-18T10:00:00Z',
            'updated_at': '2026-04-18T11:00:00Z',
        }
        payload.update(overrides)
        return payload
