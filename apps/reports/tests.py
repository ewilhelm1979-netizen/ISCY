import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.reports.models import ReportSnapshot
from apps.wizard.models import AssessmentSession


User = get_user_model()


@override_settings(REPORT_SNAPSHOT_BACKEND="local", RUST_BACKEND_URL="")
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
        self.assertEqual(response.context["report_snapshot_source"], "django")

    @patch("apps.reports.services.urlopen")
    def test_report_list_can_use_rust_snapshot_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            "api_version": "v1",
            "tenant_id": self.tenant_a.id,
            "reports": [
                {
                    "id": self.report_a.id,
                    "tenant_id": self.tenant_a.id,
                    "session_id": self.session_a.id,
                    "title": "Rust Report A",
                    "applicability_result": "relevant",
                    "iso_readiness_percent": 81,
                    "nis2_readiness_percent": 76,
                    "created_at": "2026-04-18T10:00:00Z",
                    "updated_at": "2026-04-18T11:00:00Z",
                }
            ],
        }).encode("utf-8")
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(REPORT_SNAPSHOT_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.get(reverse("reports:list"))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, "http://rust-backend:9000/api/v1/reports/snapshots")
        self.assertEqual(rust_request.get_header("X-iscy-tenant-id"), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header("X-iscy-user-id"), str(self.user_a.id))
        reports = list(response.context["reports"])
        self.assertEqual(response.context["report_snapshot_source"], "rust_service")
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].title, "Rust Report A")
        self.assertEqual(reports[0].tenant.name, "Tenant A")
        self.assertEqual(reports[0].iso_readiness_percent, 81)

    @patch("apps.reports.services.urlopen", side_effect=OSError("backend down"))
    def test_report_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            REPORT_SNAPSHOT_BACKEND="rust_service",
            RUST_BACKEND_URL="http://rust-backend:9000",
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse("reports:list"))

        self.assertEqual(response.status_code, 200)
        reports = list(response.context["reports"])
        self.assertEqual(response.context["report_snapshot_source"], "django")
        self.assertEqual(reports, [self.report_a])

    def test_report_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(REPORT_SNAPSHOT_BACKEND="rust_service", RUST_BACKEND_URL="", RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse("reports:list"))

    @patch("apps.reports.services.urlopen")
    def test_report_detail_can_use_rust_snapshot_bridge(self, mock_urlopen):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps({
            "api_version": "v1",
            "report": {
                "id": self.report_a.id,
                "tenant_id": self.tenant_a.id,
                "session_id": self.session_a.id,
                "title": "Rust Detail Report",
                "executive_summary": "Rust Executive Summary",
                "applicability_result": "relevant",
                "iso_readiness_percent": 88,
                "nis2_readiness_percent": 79,
                "kritis_readiness_percent": 33,
                "cra_readiness_percent": 34,
                "ai_act_readiness_percent": 35,
                "iec62443_readiness_percent": 36,
                "iso_sae_21434_readiness_percent": 37,
                "regulatory_matrix_json": {
                    "summary": "Rust matrix",
                    "nis2": {"label": "NIS2", "applicable": True, "reason": "Tenant relevant"},
                },
                "compliance_versions_json": {
                    "ISO27001": {
                        "framework": "ISO27001",
                        "version": "2022",
                        "title": "ISO 27001",
                        "requirement_count": 93,
                        "source_count": 1,
                    }
                },
                "product_security_json": {"sbom_required": True},
                "top_gaps_json": [{"title": "Rust Gap", "severity": "HIGH"}],
                "top_measures_json": [{"title": "Rust Measure", "priority": "HIGH"}],
                "roadmap_summary": [{"name": "Rust Phase", "duration_weeks": 4, "objective": "Bridge"}],
                "domain_scores_json": [{"domain": "Governance", "score_percent": 88, "maturity_level": "Managed"}],
                "next_steps_json": {"dependencies": []},
                "created_at": "2026-04-18T10:00:00Z",
                "updated_at": "2026-04-18T11:00:00Z",
            },
        }).encode("utf-8")
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
        self.client.force_login(self.user_a)

        with self.settings(REPORT_SNAPSHOT_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.get(reverse("reports:detail", args=[self.report_a.pk]))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f"http://rust-backend:9000/api/v1/reports/snapshots/{self.report_a.pk}",
        )
        self.assertEqual(rust_request.get_header("X-iscy-tenant-id"), str(self.tenant_a.id))
        self.assertEqual(rust_request.get_header("X-iscy-user-id"), str(self.user_a.id))
        report = response.context["report"]
        self.assertEqual(response.context["report_snapshot_source"], "rust_service")
        self.assertEqual(report.title, "Rust Detail Report")
        self.assertEqual(report.iso_readiness_percent, 88)
        self.assertEqual(report.tenant.name, "Tenant A")
        self.assertContains(response, "Rust Executive Summary")

    @patch("apps.reports.services.urlopen", side_effect=OSError("backend down"))
    def test_report_detail_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            REPORT_SNAPSHOT_BACKEND="rust_service",
            RUST_BACKEND_URL="http://rust-backend:9000",
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse("reports:detail", args=[self.report_a.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["report_snapshot_source"], "django")
        self.assertEqual(response.context["report"], self.report_a)

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
