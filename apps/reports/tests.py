from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.reports.models import ReportSnapshot
from apps.wizard.models import AssessmentSession


User = get_user_model()


class ReportViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(name="Tenant A", slug="tenant-a", country="DE")
        self.tenant_b = Tenant.objects.create(name="Tenant B", slug="tenant-b", country="DE")

        self.user_a = User.objects.create_user(
            username="tenant-a-user",
            password="testpass123",
            tenant=self.tenant_a,
        )
        self.user_b = User.objects.create_user(
            username="tenant-b-user",
            password="testpass123",
            tenant=self.tenant_b,
        )

        self.session_a = AssessmentSession.objects.create(
            tenant=self.tenant_a,
            started_by=self.user_a,
            applicability_result="relevant",
            executive_summary="Kurzfassung Tenant A",
        )
        self.session_b = AssessmentSession.objects.create(
            tenant=self.tenant_b,
            started_by=self.user_b,
            applicability_result="not_relevant",
            executive_summary="Kurzfassung Tenant B",
        )

        self.report_a = ReportSnapshot.objects.create(
            tenant=self.tenant_a,
            session=self.session_a,
            title="Report A",
            executive_summary="Executive Summary A",
            applicability_result="relevant",
            compliance_versions_json={
                "ISO27001": {"version": "2022"},
                "NIS2": {"version": "2024"},
            },
            domain_scores_json=[
                {"domain": "Governance", "score_percent": 82, "maturity_level": "Managed"}
            ],
            top_measures_json=[{"title": "MFA einführen", "priority": "HIGH"}],
            roadmap_summary=[{"name": "Phase 1", "duration_weeks": 6, "objective": "Basis schaffen"}],
            next_steps_json={"dependencies": []},
        )
        self.report_b = ReportSnapshot.objects.create(
            tenant=self.tenant_b,
            session=self.session_b,
            title="Report B",
            executive_summary="Executive Summary B",
            applicability_result="not_relevant",
        )

    def test_report_list_only_shows_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("reports:list"))

        self.assertEqual(response.status_code, 200)
        reports = list(response.context["reports"])
        self.assertEqual(reports, [self.report_a])

    def test_report_detail_blocks_foreign_tenant_access(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("reports:detail", args=[self.report_b.pk]))

        self.assertEqual(response.status_code, 404)

    def test_report_pdf_is_generated_for_own_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("reports:pdf", args=[self.report_a.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_report_pdf_blocks_foreign_tenant_access(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("reports:pdf", args=[self.report_b.pk]))

        self.assertEqual(response.status_code, 404)
