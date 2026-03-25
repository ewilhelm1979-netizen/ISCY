from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.organizations.models import Tenant
from apps.product_security.models import Product, ProductFamily, ProductSecuritySnapshot


User = get_user_model()


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
        self.assertEqual(list(response.context["products"]), [self.product_a])
        self.assertEqual(list(response.context["snapshots"]), [self.snapshot_a])
        self.assertContains(response, "Produkt A")
        self.assertNotContains(response, "Produkt B")

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
