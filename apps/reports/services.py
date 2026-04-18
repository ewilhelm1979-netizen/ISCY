import json
from dataclasses import dataclass
from urllib.request import Request, urlopen

from django.conf import settings


@dataclass(frozen=True)
class ReportTenantRef:
    id: int
    name: str


@dataclass(frozen=True)
class ReportSnapshotListItem:
    id: int
    tenant: ReportTenantRef
    tenant_id: int
    session_id: int
    title: str
    applicability_result: str
    iso_readiness_percent: int
    nis2_readiness_percent: int
    created_at: str
    updated_at: str


class ReportRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_snapshots(request, tenant, timeout: int = 8) -> list[ReportSnapshotListItem]:
        base = ReportRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Report-Rust-Bridge braucht einen authentifizierten User.')

        rust_request = Request(f'{base}/api/v1/reports/snapshots')
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
            raise RuntimeError('Rust-Reportliste gehoert nicht zum angefragten Tenant.')

        tenant_ref = ReportTenantRef(id=int(tenant.id), name=str(tenant.name))
        return [
            ReportSnapshotListItem(
                id=ReportRustClient._int_field(item, 'id'),
                tenant=tenant_ref,
                tenant_id=ReportRustClient._int_field(item, 'tenant_id'),
                session_id=ReportRustClient._int_field(item, 'session_id'),
                title=str(item.get('title') or ''),
                applicability_result=str(item.get('applicability_result') or ''),
                iso_readiness_percent=ReportRustClient._int_field(item, 'iso_readiness_percent'),
                nis2_readiness_percent=ReportRustClient._int_field(item, 'nis2_readiness_percent'),
                created_at=str(item.get('created_at') or ''),
                updated_at=str(item.get('updated_at') or ''),
            )
            for item in payload.get('reports', [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def _int_field(payload: dict, key: str) -> int:
        return int(payload.get(key) or 0)


class ReportSnapshotBridge:
    @staticmethod
    def fetch_list(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'REPORT_SNAPSHOT_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not ReportRustClient._base_url():
            if ReportSnapshotBridge._strict_rust_mode():
                raise RuntimeError('Rust report snapshot backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return ReportRustClient.fetch_snapshots(request, tenant)
        except Exception as exc:
            if ReportSnapshotBridge._strict_rust_mode():
                raise RuntimeError('Rust report snapshot backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
