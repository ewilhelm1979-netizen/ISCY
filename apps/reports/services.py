import json
from dataclasses import dataclass, field
from urllib.error import HTTPError
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


class EmptyRelatedManager:
    def first(self):
        return None


@dataclass(frozen=True)
class ReportSessionRef:
    id: int
    roadmap_plans: EmptyRelatedManager = field(default_factory=EmptyRelatedManager)


@dataclass(frozen=True)
class ReportSnapshotDetailItem:
    id: int
    tenant: object
    tenant_id: int
    session: ReportSessionRef
    session_id: int
    title: str
    executive_summary: str
    applicability_result: str
    iso_readiness_percent: int
    nis2_readiness_percent: int
    kritis_readiness_percent: int
    cra_readiness_percent: int
    ai_act_readiness_percent: int
    iec62443_readiness_percent: int
    iso_sae_21434_readiness_percent: int
    regulatory_matrix_json: dict
    compliance_versions_json: dict
    product_security_json: dict
    top_gaps_json: list
    top_measures_json: list
    roadmap_summary: list
    domain_scores_json: list
    next_steps_json: dict
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id


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
    def fetch_snapshot_detail(request, tenant, report_id: int, timeout: int = 8):
        base = ReportRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ReportRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/reports/snapshots/{int(report_id)}',
        )
        try:
            with urlopen(rust_request, timeout=timeout) as response:
                payload = json.loads(response.read().decode('utf-8'))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise

        report = payload.get('report') or {}
        if not isinstance(report, dict):
            raise RuntimeError('Rust-Reportdetail hat kein report-Objekt geliefert.')
        tenant_id = ReportRustClient._int_field(report, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Reportdetail gehoert nicht zum angefragten Tenant.')

        session_id = ReportRustClient._int_field(report, 'session_id')
        return ReportSnapshotDetailItem(
            id=ReportRustClient._int_field(report, 'id'),
            tenant=tenant,
            tenant_id=tenant_id,
            session=ReportSessionRef(id=session_id),
            session_id=session_id,
            title=str(report.get('title') or ''),
            executive_summary=str(report.get('executive_summary') or ''),
            applicability_result=str(report.get('applicability_result') or ''),
            iso_readiness_percent=ReportRustClient._int_field(report, 'iso_readiness_percent'),
            nis2_readiness_percent=ReportRustClient._int_field(report, 'nis2_readiness_percent'),
            kritis_readiness_percent=ReportRustClient._int_field(report, 'kritis_readiness_percent'),
            cra_readiness_percent=ReportRustClient._int_field(report, 'cra_readiness_percent'),
            ai_act_readiness_percent=ReportRustClient._int_field(report, 'ai_act_readiness_percent'),
            iec62443_readiness_percent=ReportRustClient._int_field(report, 'iec62443_readiness_percent'),
            iso_sae_21434_readiness_percent=ReportRustClient._int_field(
                report,
                'iso_sae_21434_readiness_percent',
            ),
            regulatory_matrix_json=ReportRustClient._dict_field(report, 'regulatory_matrix_json'),
            compliance_versions_json=ReportRustClient._dict_field(report, 'compliance_versions_json'),
            product_security_json=ReportRustClient._dict_field(report, 'product_security_json'),
            top_gaps_json=ReportRustClient._list_field(report, 'top_gaps_json'),
            top_measures_json=ReportRustClient._list_field(report, 'top_measures_json'),
            roadmap_summary=ReportRustClient._list_field(report, 'roadmap_summary'),
            domain_scores_json=ReportRustClient._list_field(report, 'domain_scores_json'),
            next_steps_json=ReportRustClient._dict_field(report, 'next_steps_json'),
            created_at=str(report.get('created_at') or ''),
            updated_at=str(report.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Report-Rust-Bridge braucht einen authentifizierten User.')

        rust_request = Request(url)
        rust_request.add_header('Accept', 'application/json')
        rust_request.add_header('X-ISCY-Tenant-ID', str(tenant.id))
        rust_request.add_header('X-ISCY-User-ID', str(user_id))
        user_email = (getattr(user, 'email', '') or '').strip()
        if user_email:
            rust_request.add_header('X-ISCY-User-Email', user_email)
        return rust_request

    @staticmethod
    def _int_field(payload: dict, key: str) -> int:
        return int(payload.get(key) or 0)

    @staticmethod
    def _dict_field(payload: dict, key: str) -> dict:
        value = payload.get(key)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list_field(payload: dict, key: str) -> list:
        value = payload.get(key)
        return value if isinstance(value, list) else []


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
    def fetch_detail(request, tenant, report_id: int):
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
            return ReportRustClient.fetch_snapshot_detail(request, tenant, report_id)
        except Exception as exc:
            if ReportSnapshotBridge._strict_rust_mode():
                raise RuntimeError('Rust report snapshot backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
