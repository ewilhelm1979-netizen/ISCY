from django.test import TestCase
from django.urls import reverse


class HealthViewTests(TestCase):
    def test_live_health(self):
        response = self.client.get(reverse('health_live'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ok')

    def test_ready_health(self):
        response = self.client.get(reverse('health_ready'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['database'], 'ok')
