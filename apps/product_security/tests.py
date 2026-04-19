import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.product_security.models import Product, ProductFamily, ProductSecuritySnapshot


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

    def _mock_rust_response(self, mock_urlopen, payload):
        response_mock = Mock()
        response_mock.read.return_value = json.dumps(payload).encode("utf-8")
        response_ctx = Mock()
        response_ctx.__enter__ = Mock(return_value=response_mock)
        response_ctx.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = response_ctx
