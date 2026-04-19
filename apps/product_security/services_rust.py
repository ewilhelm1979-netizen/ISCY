import json
from dataclasses import dataclass
from urllib.request import Request, urlopen

from django.conf import settings


@dataclass(frozen=True)
class ProductSecurityRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ProductSecurityRelatedCount:
    value: int

    def count(self) -> int:
        return self.value


@dataclass(frozen=True)
class ProductSecurityProductListItem:
    id: int
    tenant: object
    tenant_id: int
    family: ProductSecurityRelatedRef | None
    family_id: int | None
    name: str
    code: str
    description: str
    has_digital_elements: bool
    includes_ai: bool
    ot_iacs_context: bool
    automotive_context: bool
    support_window_months: int
    releases: ProductSecurityRelatedCount
    threat_models: ProductSecurityRelatedCount
    taras: ProductSecurityRelatedCount
    vulnerabilities: ProductSecurityRelatedCount
    psirt_cases: ProductSecurityRelatedCount
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id


@dataclass(frozen=True)
class ProductSecuritySnapshotListItem:
    id: int
    tenant: object
    tenant_id: int
    product: ProductSecurityRelatedRef
    product_id: int
    cra_applicable: bool
    ai_act_applicable: bool
    iec62443_applicable: bool
    iso_sae_21434_applicable: bool
    cra_readiness_percent: int
    ai_act_readiness_percent: int
    iec62443_readiness_percent: int
    iso_sae_21434_readiness_percent: int
    threat_model_coverage_percent: int
    psirt_readiness_percent: int
    open_vulnerability_count: int
    critical_vulnerability_count: int
    summary: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id


@dataclass(frozen=True)
class ProductSecurityOverviewBridgeResult:
    products: list[ProductSecurityProductListItem]
    snapshots: list[ProductSecuritySnapshotListItem]
    matrix: dict
    posture: dict


class ProductSecurityRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_overview(request, tenant, timeout: int = 8) -> ProductSecurityOverviewBridgeResult:
        base = ProductSecurityRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ProductSecurityRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/product-security/overview',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = ProductSecurityRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Product-Security-Uebersicht gehoert nicht zum angefragten Tenant.')

        return ProductSecurityOverviewBridgeResult(
            products=[
                ProductSecurityRustClient._product_from_payload(item, tenant)
                for item in payload.get('products', [])
                if isinstance(item, dict)
            ],
            snapshots=[
                ProductSecurityRustClient._snapshot_from_payload(item, tenant)
                for item in payload.get('snapshots', [])
                if isinstance(item, dict)
            ],
            matrix=payload.get('matrix') if isinstance(payload.get('matrix'), dict) else {},
            posture=payload.get('posture') if isinstance(payload.get('posture'), dict) else {},
        )

    @staticmethod
    def _product_from_payload(item: dict, tenant) -> ProductSecurityProductListItem:
        family_id = ProductSecurityRustClient._optional_int_field(item, 'family_id')
        family_name = str(item.get('family_name') or '').strip()
        return ProductSecurityProductListItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            family=ProductSecurityRelatedRef(family_id, family_name) if family_name else None,
            family_id=family_id,
            name=str(item.get('name') or ''),
            code=str(item.get('code') or ''),
            description=str(item.get('description') or ''),
            has_digital_elements=bool(item.get('has_digital_elements')),
            includes_ai=bool(item.get('includes_ai')),
            ot_iacs_context=bool(item.get('ot_iacs_context')),
            automotive_context=bool(item.get('automotive_context')),
            support_window_months=ProductSecurityRustClient._int_field(item, 'support_window_months'),
            releases=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'release_count')),
            threat_models=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'threat_model_count')),
            taras=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'tara_count')),
            vulnerabilities=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'vulnerability_count')),
            psirt_cases=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'psirt_case_count')),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _snapshot_from_payload(item: dict, tenant) -> ProductSecuritySnapshotListItem:
        product_id = ProductSecurityRustClient._int_field(item, 'product_id')
        product_name = str(item.get('product_name') or '').strip()
        return ProductSecuritySnapshotListItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product=ProductSecurityRelatedRef(product_id, product_name),
            product_id=product_id,
            cra_applicable=bool(item.get('cra_applicable')),
            ai_act_applicable=bool(item.get('ai_act_applicable')),
            iec62443_applicable=bool(item.get('iec62443_applicable')),
            iso_sae_21434_applicable=bool(item.get('iso_sae_21434_applicable')),
            cra_readiness_percent=ProductSecurityRustClient._int_field(item, 'cra_readiness_percent'),
            ai_act_readiness_percent=ProductSecurityRustClient._int_field(item, 'ai_act_readiness_percent'),
            iec62443_readiness_percent=ProductSecurityRustClient._int_field(item, 'iec62443_readiness_percent'),
            iso_sae_21434_readiness_percent=ProductSecurityRustClient._int_field(item, 'iso_sae_21434_readiness_percent'),
            threat_model_coverage_percent=ProductSecurityRustClient._int_field(item, 'threat_model_coverage_percent'),
            psirt_readiness_percent=ProductSecurityRustClient._int_field(item, 'psirt_readiness_percent'),
            open_vulnerability_count=ProductSecurityRustClient._int_field(item, 'open_vulnerability_count'),
            critical_vulnerability_count=ProductSecurityRustClient._int_field(item, 'critical_vulnerability_count'),
            summary=str(item.get('summary') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Product-Security-Rust-Bridge braucht einen authentifizierten User.')

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
    def _optional_int_field(payload: dict, key: str) -> int | None:
        value = payload.get(key)
        if value in (None, ''):
            return None
        return int(value)


class ProductSecurityBridge:
    @staticmethod
    def fetch_overview(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'PRODUCT_SECURITY_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not ProductSecurityRustClient._base_url():
            if ProductSecurityBridge._strict_rust_mode():
                raise RuntimeError('Rust product security backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return ProductSecurityRustClient.fetch_overview(request, tenant)
        except Exception as exc:
            if ProductSecurityBridge._strict_rust_mode():
                raise RuntimeError('Rust product security backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
