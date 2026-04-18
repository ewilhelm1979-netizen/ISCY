import json
from urllib.request import Request, urlopen

from django.conf import settings


class DashboardRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_summary(request, tenant, timeout: int = 8) -> dict:
        base = DashboardRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Dashboard-Rust-Bridge braucht einen authentifizierten User.')

        rust_request = Request(f'{base}/api/v1/dashboard/summary')
        rust_request.add_header('Accept', 'application/json')
        rust_request.add_header('X-ISCY-Tenant-ID', str(tenant.id))
        rust_request.add_header('X-ISCY-User-ID', str(user_id))
        user_email = (getattr(user, 'email', '') or '').strip()
        if user_email:
            rust_request.add_header('X-ISCY-User-Email', user_email)

        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = int(payload.get('tenant_id') or 0)
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Dashboard-Summary gehoert nicht zum angefragten Tenant.')

        return {
            'process_count': DashboardRustClient._int_field(payload, 'process_count'),
            'asset_count': DashboardRustClient._int_field(payload, 'asset_count'),
            'open_risk_count': DashboardRustClient._int_field(payload, 'open_risk_count'),
            'evidence_count': DashboardRustClient._int_field(payload, 'evidence_count'),
            'open_task_count': DashboardRustClient._int_field(payload, 'open_task_count'),
            'latest_report': payload.get('latest_report') or None,
        }

    @staticmethod
    def _int_field(payload: dict, key: str) -> int:
        return int(payload.get(key) or 0)


class DashboardSummaryBridge:
    @staticmethod
    def fetch(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'DASHBOARD_SUMMARY_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not DashboardRustClient._base_url():
            if DashboardSummaryBridge._strict_rust_mode():
                raise RuntimeError('Rust dashboard summary backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return DashboardRustClient.fetch_summary(request, tenant)
        except Exception as exc:
            if DashboardSummaryBridge._strict_rust_mode():
                raise RuntimeError('Rust dashboard summary backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
