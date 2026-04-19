import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.product_security.models import Product, ProductFamily, ProductSecuritySnapshot, Vulnerability
from apps.product_security.services import ProductSecurityService


User = get_user_model()


@override_settings(PRODUCT_SECURITY_BACKEND='local', RUST_BACKEND_URL='')
class ProductSecurityViewTests(TestCase):
    def setUp(self):
        self.tenant_a = Tenant.objects.create(
            name="Tenant A",
            slug="tenant-a-ps",
            country="DE",
            develops_digital_products=True,
        )
        self.tenant_b = Tenant.objects.create(
            name="Tenant B",
            slug="tenant-b-ps",
            country="DE",
            develops_digital_products=True,
        )

        self.user_a = User.objects.create_user(
            username="product-security-a",
            password="testpass123",
            tenant=self.tenant_a,
        )
        self.user_b = User.objects.create_user(
            username="product-security-b",
            password="testpass123",
            tenant=self.tenant_b,
        )

        self.family_a = ProductFamily.objects.create(tenant=self.tenant_a, name="Familie A")
        self.family_b = ProductFamily.objects.create(tenant=self.tenant_b, name="Familie B")

        self.product_a = Product.objects.create(
            tenant=self.tenant_a,
            family=self.family_a,
            name="Produkt A",
            has_digital_elements=True,
        )
        self.product_b = Product.objects.create(
            tenant=self.tenant_b,
            family=self.family_b,
            name="Produkt B",
            has_digital_elements=True,
        )

        self.snapshot_a = ProductSecuritySnapshot.objects.create(
            tenant=self.tenant_a,
            product=self.product_a,
            cra_applicable=True,
            cra_readiness_percent=72,
            threat_model_coverage_percent=40,
            psirt_readiness_percent=55,
            open_vulnerability_count=2,
            critical_vulnerability_count=1,
            summary="Snapshot Tenant A",
        )
        self.snapshot_b = ProductSecuritySnapshot.objects.create(
            tenant=self.tenant_b,
            product=self.product_b,
            cra_applicable=True,
            cra_readiness_percent=33,
            summary="Snapshot Tenant B",
        )
        self.vulnerability_a = Vulnerability.objects.create(
            tenant=self.tenant_a,
            product=self.product_a,
            title="Tenant A Vulnerability",
            cve="CVE-2026-4242",
            severity=Vulnerability.Severity.HIGH,
            status=Vulnerability.Status.OPEN,
            remediation_due="2026-06-01",
            summary="Tenant A vulnerability summary",
        )
        self.vulnerability_b = Vulnerability.objects.create(
            tenant=self.tenant_b,
            product=self.product_b,
            title="Tenant B Vulnerability",
            severity=Vulnerability.Severity.CRITICAL,
            status=Vulnerability.Status.OPEN,
            summary="Tenant B vulnerability summary",
        )

    def test_product_list_only_shows_current_tenant_products_and_snapshots(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("product_security:list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["product_security_source"], "django")
        self.assertEqual(list(response.context["products"]), [self.product_a])
        self.assertEqual(list(response.context["snapshots"]), [self.snapshot_a])
        self.assertContains(response, "Produkt A")
        self.assertNotContains(response, "Produkt B")

    @patch("apps.product_security.services_rust.urlopen")
    def test_product_list_can_use_rust_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_payload())
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.get(reverse("product_security:list"))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(rust_request.full_url, "http://rust-backend:9000/api/v1/product-security/overview")
        self.assertEqual(rust_request.get_header("X-iscy-tenant-id"), str(self.tenant_a.id))
        self.assertEqual(response.context["product_security_source"], "rust_service")
        self.assertEqual(len(response.context["products"]), 1)
        self.assertEqual(response.context["posture"]["products"], 1)
        self.assertContains(response, "Rust Produkt")
        self.assertContains(response, "Rust Product Security ist aktiv")

    @patch("apps.product_security.services_rust.urlopen", side_effect=OSError("backend down"))
    def test_product_list_falls_back_to_django_when_rust_unavailable_in_non_strict_mode(self, _mock_urlopen):
        self.client.force_login(self.user_a)

        with self.settings(
            PRODUCT_SECURITY_BACKEND="rust_service",
            RUST_BACKEND_URL="http://rust-backend:9000",
            RUST_STRICT_MODE=False,
        ):
            response = self.client.get(reverse("product_security:list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["product_security_source"], "django")
        self.assertContains(response, "Produkt A")

    def test_product_list_raises_in_strict_mode_without_rust_backend_url(self):
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="", RUST_STRICT_MODE=True):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse("product_security:list"))

    def test_product_detail_blocks_foreign_tenant_access(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("product_security:detail", args=[self.product_b.pk]))

        self.assertEqual(response.status_code, 404)

    def test_product_detail_generates_roadmap_for_current_tenant(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("product_security:detail", args=[self.product_a.pk]))

        self.assertEqual(response.status_code, 200)
        roadmap = self.product_a.roadmaps.first()
        self.assertIsNotNone(roadmap)
        self.assertGreater(roadmap.tasks.count(), 0)
        self.assertContains(response, "Product-Security-Roadmap")

    @patch("apps.product_security.services_rust.urlopen")
    def test_product_detail_can_use_rust_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_detail_payload())
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.get(reverse("product_security:detail", args=[self.product_a.pk]))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f"http://rust-backend:9000/api/v1/product-security/products/{self.product_a.id}",
        )
        self.assertEqual(response.context["product_security_source"], "rust_service")
        self.assertContains(response, "Rust Firmware")
        self.assertContains(response, "Rust Threat Model")
        self.assertContains(response, "Rust Roadmap Task")

    def test_product_roadmap_blocks_foreign_tenant_access(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("product_security:roadmap", args=[self.product_b.pk]))

        self.assertEqual(response.status_code, 404)

    def test_product_roadmap_renders_generated_tasks(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("product_security:roadmap", args=[self.product_a.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Governance")
        self.assertContains(response, "Produkt-Scope, Verantwortlichkeiten und Security Sign-off festigen")

    @patch("apps.product_security.services_rust.urlopen")
    def test_product_roadmap_can_use_rust_bridge(self, mock_urlopen):
        self._mock_rust_response(mock_urlopen, self._rust_roadmap_payload())
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.get(reverse("product_security:roadmap", args=[self.product_a.pk]))

        self.assertEqual(response.status_code, 200)
        rust_request = mock_urlopen.call_args.args[0]
        self.assertEqual(
            rust_request.full_url,
            f"http://rust-backend:9000/api/v1/product-security/products/{self.product_a.id}/roadmap",
        )
        self.assertEqual(response.context["product_security_source"], "rust_service")
        self.assertContains(response, "Rust Product Roadmap")
        self.assertContains(response, "Rust Roadmap Task")

    def test_product_roadmap_task_update_uses_local_backend(self):
        roadmap = ProductSecurityService.generate_product_roadmap(self.product_a)
        task = roadmap.tasks.first()
        self.client.force_login(self.user_a)

        response = self.client.post(
            reverse("product_security:roadmap-task-edit", args=[task.pk]),
            {
                "status": "DONE",
                "priority": "MEDIUM",
                "owner_role": "Product Security Office",
                "due_in_days": "9",
                "dependency_text": "Reviewed locally",
            },
        )

        self.assertRedirects(
            response,
            reverse("product_security:roadmap", args=[self.product_a.pk]),
            fetch_redirect_response=False,
        )
        task.refresh_from_db()
        self.assertEqual(task.status, "DONE")
        self.assertEqual(task.priority, "MEDIUM")
        self.assertEqual(task.owner_role, "Product Security Office")
        self.assertEqual(task.due_in_days, 9)
        self.assertEqual(task.dependency_text, "Reviewed locally")

    @patch("apps.product_security.services_rust.urlopen")
    def test_product_roadmap_task_update_can_use_rust_bridge(self, mock_urlopen):
        roadmap = ProductSecurityService.generate_product_roadmap(self.product_a)
        task = roadmap.tasks.first()
        task_payload = self._rust_roadmap_task_payload()
        task_payload.update({
            "id": task.id,
            "roadmap_id": roadmap.id,
            "status": "DONE",
            "status_label": "Erledigt",
            "priority": "MEDIUM",
            "owner_role": "Product Security Office",
            "due_in_days": 9,
            "dependency_text": "Reviewed in Rust",
        })
        self._mock_rust_response(mock_urlopen, {
            "api_version": "v1",
            "product_id": self.product_a.id,
            "roadmap_id": roadmap.id,
            "task": task_payload,
        })
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.post(
                reverse("product_security:roadmap-task-edit", args=[task.pk]),
                {
                    "status": "DONE",
                    "priority": "MEDIUM",
                    "owner_role": "Product Security Office",
                    "due_in_days": "9",
                    "dependency_text": "Reviewed in Rust",
                },
            )

        self.assertRedirects(
            response,
            reverse("product_security:roadmap", args=[self.product_a.pk]),
            fetch_redirect_response=False,
        )
        rust_request = mock_urlopen.call_args.args[0]
        body = json.loads(rust_request.data.decode("utf-8"))
        self.assertEqual(
            rust_request.full_url,
            f"http://rust-backend:9000/api/v1/product-security/roadmap-tasks/{task.id}",
        )
        self.assertEqual(rust_request.get_method(), "PATCH")
        self.assertEqual(body["status"], "DONE")
        self.assertEqual(body["owner_role"], "Product Security Office")
        self.assertEqual(body["due_in_days"], 9)

    def test_product_roadmap_task_update_blocks_foreign_tenant_access(self):
        roadmap = ProductSecurityService.generate_product_roadmap(self.product_b)
        task = roadmap.tasks.first()
        self.client.force_login(self.user_a)

        response = self.client.post(
            reverse("product_security:roadmap-task-edit", args=[task.pk]),
            {
                "status": "DONE",
                "priority": "MEDIUM",
                "owner_role": "Product Security Office",
                "due_in_days": "9",
                "dependency_text": "Nope",
            },
        )

        self.assertEqual(response.status_code, 404)

    def test_product_vulnerability_update_uses_local_backend(self):
        self.client.force_login(self.user_a)

        response = self.client.post(
            reverse("product_security:vulnerability-edit", args=[self.vulnerability_a.pk]),
            {
                "severity": "MEDIUM",
                "status": "MITIGATED",
                "remediation_due": "2026-06-15",
                "summary": "Mitigated locally",
            },
        )

        self.assertRedirects(
            response,
            reverse("product_security:detail", args=[self.product_a.pk]),
            fetch_redirect_response=False,
        )
        self.vulnerability_a.refresh_from_db()
        self.assertEqual(self.vulnerability_a.severity, "MEDIUM")
        self.assertEqual(self.vulnerability_a.status, "MITIGATED")
        self.assertEqual(self.vulnerability_a.remediation_due.isoformat(), "2026-06-15")
        self.assertEqual(self.vulnerability_a.summary, "Mitigated locally")

    @patch("apps.product_security.services_rust.urlopen")
    def test_product_vulnerability_update_can_use_rust_bridge(self, mock_urlopen):
        vulnerability_payload = self._rust_detail_payload()["vulnerabilities"][0]
        vulnerability_payload.update({
            "id": self.vulnerability_a.id,
            "product_id": self.product_a.id,
            "severity": "MEDIUM",
            "severity_label": "Mittel",
            "status": "MITIGATED",
            "status_label": "Mitigiert",
            "remediation_due": "2026-06-15",
            "summary": "Mitigated in Rust",
        })
        self._mock_rust_response(mock_urlopen, {
            "api_version": "v1",
            "product_id": self.product_a.id,
            "vulnerability": vulnerability_payload,
        })
        self.client.force_login(self.user_a)

        with self.settings(PRODUCT_SECURITY_BACKEND="rust_service", RUST_BACKEND_URL="http://rust-backend:9000"):
            response = self.client.post(
                reverse("product_security:vulnerability-edit", args=[self.vulnerability_a.pk]),
                {
                    "severity": "MEDIUM",
                    "status": "MITIGATED",
                    "remediation_due": "2026-06-15",
                    "summary": "Mitigated in Rust",
                },
            )

        self.assertRedirects(
            response,
            reverse("product_security:detail", args=[self.product_a.pk]),
            fetch_redirect_response=False,
        )
        rust_request = mock_urlopen.call_args.args[0]
        body = json.loads(rust_request.data.decode("utf-8"))
        self.assertEqual(
            rust_request.full_url,
            f"http://rust-backend:9000/api/v1/product-security/vulnerabilities/{self.vulnerability_a.id}",
        )
        self.assertEqual(rust_request.get_method(), "PATCH")
        self.assertEqual(body["severity"], "MEDIUM")
        self.assertEqual(body["status"], "MITIGATED")
        self.assertEqual(body["remediation_due"], "2026-06-15")
        self.assertEqual(body["summary"], "Mitigated in Rust")

    def test_product_vulnerability_update_blocks_foreign_tenant_access(self):
        self.client.force_login(self.user_a)

        response = self.client.post(
            reverse("product_security:vulnerability-edit", args=[self.vulnerability_b.pk]),
            {
                "severity": "LOW",
                "status": "ACCEPTED",
                "remediation_due": "",
                "summary": "Nope",
            },
        )

        self.assertEqual(response.status_code, 404)

    def _rust_payload(self):
        return {
            "api_version": "v1",
            "tenant_id": self.tenant_a.id,
            "matrix": {
                "cra": {
                    "applicable": True,
                    "label": "CRA",
                    "reason": "Relevant fuer Produkte mit digitalen Elementen.",
                },
                "ai_act": {
                    "applicable": False,
                    "label": "AI Act",
                    "reason": "Kein AI-Scope.",
                },
                "iec62443": {
                    "applicable": False,
                    "label": "IEC 62443",
                    "reason": "Kein OT-Scope.",
                },
                "iso_sae_21434": {
                    "applicable": False,
                    "label": "ISO/SAE 21434",
                    "reason": "Kein Automotive-Scope.",
                },
                "summary": "Rust Product Security ist aktiv.",
            },
            "posture": {
                "products": 1,
                "active_releases": 2,
                "threat_models": 3,
                "taras": 4,
                "open_vulnerabilities": 5,
                "critical_open_vulnerabilities": 1,
                "psirt_cases_open": 2,
                "published_advisories": 1,
                "avg_threat_model_coverage": 40,
                "avg_psirt_readiness": 55,
            },
            "products": [{
                "id": self.product_a.id,
                "tenant_id": self.tenant_a.id,
                "family_id": self.family_a.id,
                "family_name": "Rust Familie",
                "name": "Rust Produkt",
                "code": "rust-produkt",
                "description": "Rust product overview",
                "has_digital_elements": True,
                "includes_ai": False,
                "ot_iacs_context": False,
                "automotive_context": False,
                "support_window_months": 24,
                "release_count": 2,
                "threat_model_count": 3,
                "tara_count": 4,
                "vulnerability_count": 5,
                "psirt_case_count": 2,
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "snapshots": [{
                "id": self.snapshot_a.id,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "product_name": "Rust Produkt",
                "cra_applicable": True,
                "ai_act_applicable": False,
                "iec62443_applicable": False,
                "iso_sae_21434_applicable": False,
                "cra_readiness_percent": 72,
                "ai_act_readiness_percent": 0,
                "iec62443_readiness_percent": 0,
                "iso_sae_21434_readiness_percent": 0,
                "threat_model_coverage_percent": 40,
                "psirt_readiness_percent": 55,
                "open_vulnerability_count": 2,
                "critical_vulnerability_count": 1,
                "summary": "Rust Snapshot",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
        }

    def _rust_detail_payload(self):
        payload = self._rust_payload()
        product = payload["products"][0]
        snapshot = payload["snapshots"][0]
        return {
            "api_version": "v1",
            "product": product,
            "releases": [{
                "id": 200,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "version": "1.0",
                "status": "ACTIVE",
                "status_label": "Aktiv",
                "release_date": "2026-04-01",
                "support_end_date": "2028-04-01",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "components": [{
                "id": 250,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "supplier_id": None,
                "supplier_name": None,
                "name": "Rust Firmware",
                "component_type": "FIRMWARE",
                "component_type_label": "Firmware",
                "version": "1.0.3",
                "is_open_source": False,
                "has_sbom": True,
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "threat_models": [{
                "id": 300,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "release_id": 200,
                "release_version": "1.0",
                "name": "Rust Threat Model",
                "methodology": "STRIDE",
                "summary": "Rust threat summary",
                "status": "APPROVED",
                "status_label": "Freigegeben",
                "scenario_count": 1,
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "threat_scenarios": 1,
            "taras": [{
                "id": 400,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "release_id": 200,
                "release_version": "1.0",
                "scenario_id": 301,
                "scenario_title": "Rust scenario",
                "name": "Rust TARA",
                "summary": "Rust TARA summary",
                "attack_feasibility": 3,
                "impact_score": 4,
                "risk_score": 12,
                "status": "OPEN",
                "status_label": "Offen",
                "treatment_decision": "Mitigate",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "vulnerabilities": [{
                "id": 500,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "release_id": 200,
                "release_version": "1.0",
                "component_id": 250,
                "component_name": "Rust Firmware",
                "title": "Rust Critical Finding",
                "cve": "CVE-2026-0001",
                "severity": "CRITICAL",
                "severity_label": "Kritisch",
                "status": "OPEN",
                "status_label": "Offen",
                "remediation_due": "2026-05-18",
                "summary": "Rust vulnerability summary",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "ai_systems": [{
                "id": 260,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "product_name": "Rust Produkt",
                "name": "Rust AI Assistant",
                "use_case": "Support triage",
                "provider": "Internal",
                "risk_classification": "LIMITED",
                "risk_classification_label": "Begrenztes Risiko",
                "in_scope": True,
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "psirt_cases": [{
                "id": 600,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "release_id": 200,
                "release_version": "1.0",
                "vulnerability_id": 500,
                "vulnerability_title": "Rust Critical Finding",
                "case_id": "RUST-PSIRT-1",
                "title": "Rust PSIRT Case",
                "severity": "CRITICAL",
                "severity_label": "Kritisch",
                "status": "TRIAGE",
                "status_label": "Triage",
                "disclosure_due": "2026-05-20",
                "summary": "Rust PSIRT summary",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "advisories": [{
                "id": 700,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "release_id": 200,
                "release_version": "1.0",
                "psirt_case_id": 600,
                "psirt_case_identifier": "RUST-PSIRT-1",
                "advisory_id": "RUST-ADV-1",
                "title": "Rust Advisory",
                "status": "PUBLISHED",
                "status_label": "Veröffentlicht",
                "published_on": "2026-05-21",
                "summary": "Rust advisory summary",
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            }],
            "snapshot": snapshot,
            "roadmap": {
                "id": 900,
                "tenant_id": self.tenant_a.id,
                "product_id": self.product_a.id,
                "title": "Rust Product Roadmap",
                "summary": "Rust roadmap summary",
                "generated_from_snapshot_id": self.snapshot_a.id,
                "created_at": "2026-04-19T10:00:00Z",
                "updated_at": "2026-04-19T11:00:00Z",
            },
            "roadmap_tasks": [self._rust_roadmap_task_payload()],
        }

    def _rust_roadmap_payload(self):
        detail = self._rust_detail_payload()
        return {
            "api_version": "v1",
            "product": detail["product"],
            "roadmap": detail["roadmap"],
            "tasks": detail["roadmap_tasks"],
            "snapshot": detail["snapshot"],
        }

    def _rust_roadmap_task_payload(self):
        return {
            "id": 901,
            "tenant_id": self.tenant_a.id,
            "roadmap_id": 900,
            "related_release_id": 200,
            "related_release_version": "1.0",
            "related_vulnerability_id": 500,
            "related_vulnerability_title": "Rust Critical Finding",
            "phase": "GOVERNANCE",
            "phase_label": "Governance",
            "title": "Rust Roadmap Task",
            "description": "Task delivered from Rust",
            "priority": "HIGH",
            "owner_role": "Product Security Lead",
            "due_in_days": 30,
            "dependency_text": "",
            "status": "OPEN",
            "status_label": "Offen",
            "created_at": "2026-04-19T10:00:00Z",
            "updated_at": "2026-04-19T11:00:00Z",
        }

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode("utf-8")
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
