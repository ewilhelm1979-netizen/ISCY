from django.test import TestCase
from django.urls import reverse
from django.conf import settings


class HealthViewTests(TestCase):
    def test_live_health(self):
        response = self.client.get(reverse('health_live'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ok')

    def test_ready_health(self):
        response = self.client.get(reverse('health_ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['database'], 'ok')

    def test_rust_strict_mode_default_enabled(self):
        self.assertTrue(settings.RUST_STRICT_MODE)


class WebUiParitySmokeTests(TestCase):
    """Smoke checks that core web entry points still exist after Rust backend migration."""

    def test_primary_mount_points_are_reachable_or_protected(self):
        # 200 = public/health/login, 302 = auth protection redirect to login.
        allowed_statuses = {200, 302}
        paths = [
            '/login/',
            '/',
            '/navigator/',
            '/dashboard/',
            '/catalog/',
            '/reports/',
            '/roadmap/',
            '/evidence/',
            '/assets/',
            '/imports/',
            '/processes/',
            '/requirements/',
            '/risks/',
            '/assessments/',
            '/organizations/',
            '/product-security/',
            '/cves/',
        ]
        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path, follow=False)
                self.assertIn(response.status_code, allowed_statuses)

    def test_key_named_routes_still_resolve(self):
        # These route names represent core user-facing flows present before Rust service integration.
        route_names = [
            'wizard:start',
            'dashboard:home',
            'guidance:dashboard',
            'catalog:domains',
            'reports:list',
            'roadmap:list',
            'evidence:list',
            'assets:list',
            'imports:center',
            'processes:list',
            'requirements:list',
            'risks:list',
            'assessments:list',
            'organizations:list',
            'product_security:list',
            'vulnerability_intelligence:dashboard',
        ]
        for name in route_names:
            with self.subTest(route_name=name):
                self.assertTrue(reverse(name))
