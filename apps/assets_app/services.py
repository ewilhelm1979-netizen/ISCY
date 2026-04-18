import json
from dataclasses import dataclass
from urllib.request import Request, urlopen

from django.conf import settings


@dataclass(frozen=True)
class AssetRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class InformationAssetListItem:
    id: int
    tenant: object
    tenant_id: int
    business_unit: AssetRelatedRef | None
    business_unit_id: int | None
    owner: AssetRelatedRef | None
    owner_id: int | None
    name: str
    asset_type: str
    asset_type_label: str
    criticality: str
    criticality_label: str
    description: str
    confidentiality: str
    integrity: str
    availability: str
    lifecycle_status: str
    is_in_scope: bool
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_asset_type_display(self) -> str:
        return self.asset_type_label

    def get_criticality_display(self) -> str:
        return self.criticality_label


class AssetRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_assets(request, tenant, timeout: int = 8) -> list[InformationAssetListItem]:
        base = AssetRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = AssetRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/assets/information-assets',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = AssetRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Assetliste gehoert nicht zum angefragten Tenant.')

        return [
            AssetRustClient._asset_from_payload(item, tenant)
            for item in payload.get('assets', [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def _asset_from_payload(item: dict, tenant) -> InformationAssetListItem:
        business_unit_id = AssetRustClient._optional_int_field(item, 'business_unit_id')
        business_unit_name = str(item.get('business_unit_name') or '').strip()
        owner_id = AssetRustClient._optional_int_field(item, 'owner_id')
        owner_display = str(item.get('owner_display') or '').strip()
        return InformationAssetListItem(
            id=AssetRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=AssetRustClient._int_field(item, 'tenant_id'),
            business_unit=AssetRelatedRef(business_unit_id, business_unit_name) if business_unit_name else None,
            business_unit_id=business_unit_id,
            owner=AssetRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            name=str(item.get('name') or ''),
            asset_type=str(item.get('asset_type') or ''),
            asset_type_label=str(item.get('asset_type_label') or item.get('asset_type') or ''),
            criticality=str(item.get('criticality') or ''),
            criticality_label=str(item.get('criticality_label') or item.get('criticality') or ''),
            description=str(item.get('description') or ''),
            confidentiality=str(item.get('confidentiality') or ''),
            integrity=str(item.get('integrity') or ''),
            availability=str(item.get('availability') or ''),
            lifecycle_status=str(item.get('lifecycle_status') or ''),
            is_in_scope=bool(item.get('is_in_scope')),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Asset-Rust-Bridge braucht einen authentifizierten User.')

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


class AssetInventoryBridge:
    @staticmethod
    def fetch_list(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'ASSET_INVENTORY_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not AssetRustClient._base_url():
            if AssetInventoryBridge._strict_rust_mode():
                raise RuntimeError('Rust asset inventory backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return AssetRustClient.fetch_assets(request, tenant)
        except Exception as exc:
            if AssetInventoryBridge._strict_rust_mode():
                raise RuntimeError('Rust asset inventory backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
