import json
from dataclasses import dataclass
from datetime import date, datetime
from urllib.request import Request, urlopen

from django.conf import settings


@dataclass(frozen=True)
class RequirementMappingVersionBridgeItem:
    id: int
    framework: str
    slug: str
    title: str
    version: str
    program_name: str
    status: str
    status_label: str
    effective_on: date | None
    notes: str
    source_count: int
    requirement_count: int
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class RequirementRegulatorySourceBridgeItem:
    id: int
    framework: str
    code: str
    title: str
    authority: str
    citation: str
    url: str
    source_type: str

    @property
    def pk(self) -> int:
        return self.id


@dataclass(frozen=True)
class RequirementBridgeItem:
    id: int
    framework: str
    framework_label: str
    code: str
    title: str
    domain: str
    description: str
    guidance: str
    is_active: bool
    evidence_required: bool
    evidence_guidance: str
    evidence_examples: str
    sector_package: str
    legal_reference: str
    coverage_level: str
    coverage_level_label: str
    mapping_version: RequirementMappingVersionBridgeItem | None
    primary_source: RequirementRegulatorySourceBridgeItem | None
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_framework_display(self) -> str:
        return self.framework_label

    def get_coverage_level_display(self) -> str:
        return self.coverage_level_label


@dataclass(frozen=True)
class RequirementLibraryBridgeResult:
    requirements: list[RequirementBridgeItem]
    mapping_versions: dict[str, dict]


class RequirementRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_library(request, timeout: int = 8) -> RequirementLibraryBridgeResult:
        base = RequirementRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RequirementRustClient._authenticated_request(request, f'{base}/api/v1/requirements')
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        versions = [
            RequirementRustClient._mapping_version_from_payload(item)
            for item in payload.get('mapping_versions', [])
            if isinstance(item, dict)
        ]
        return RequirementLibraryBridgeResult(
            requirements=[
                RequirementRustClient._requirement_from_payload(item)
                for item in payload.get('requirements', [])
                if isinstance(item, dict)
            ],
            mapping_versions={
                version.framework: {
                    'framework': version.framework,
                    'title': version.title,
                    'version': version.version,
                    'program_name': version.program_name,
                    'effective_on': version.effective_on.isoformat() if version.effective_on else '',
                    'source_count': version.source_count,
                    'requirement_count': version.requirement_count,
                    'notes': version.notes,
                }
                for version in versions
            },
        )

    @staticmethod
    def _requirement_from_payload(item: dict) -> RequirementBridgeItem:
        mapping_payload = item.get('mapping_version')
        source_payload = item.get('primary_source')
        return RequirementBridgeItem(
            id=int(item.get('id') or 0),
            framework=str(item.get('framework') or ''),
            framework_label=str(item.get('framework_label') or ''),
            code=str(item.get('code') or ''),
            title=str(item.get('title') or ''),
            domain=str(item.get('domain') or ''),
            description=str(item.get('description') or ''),
            guidance=str(item.get('guidance') or ''),
            is_active=bool(item.get('is_active')),
            evidence_required=bool(item.get('evidence_required')),
            evidence_guidance=str(item.get('evidence_guidance') or ''),
            evidence_examples=str(item.get('evidence_examples') or ''),
            sector_package=str(item.get('sector_package') or ''),
            legal_reference=str(item.get('legal_reference') or ''),
            coverage_level=str(item.get('coverage_level') or ''),
            coverage_level_label=str(item.get('coverage_level_label') or ''),
            mapping_version=RequirementRustClient._mapping_version_from_payload(mapping_payload)
            if isinstance(mapping_payload, dict)
            else None,
            primary_source=RequirementRustClient._source_from_payload(source_payload)
            if isinstance(source_payload, dict)
            else None,
            created_at=RequirementRustClient._datetime_field(item.get('created_at')),
            updated_at=RequirementRustClient._datetime_field(item.get('updated_at')),
        )

    @staticmethod
    def _mapping_version_from_payload(item: dict) -> RequirementMappingVersionBridgeItem:
        return RequirementMappingVersionBridgeItem(
            id=int(item.get('id') or 0),
            framework=str(item.get('framework') or ''),
            slug=str(item.get('slug') or ''),
            title=str(item.get('title') or ''),
            version=str(item.get('version') or ''),
            program_name=str(item.get('program_name') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or ''),
            effective_on=RequirementRustClient._date_field(item.get('effective_on')),
            notes=str(item.get('notes') or ''),
            source_count=int(item.get('source_count') or 0),
            requirement_count=int(item.get('requirement_count') or 0),
            created_at=RequirementRustClient._datetime_field(item.get('created_at')),
            updated_at=RequirementRustClient._datetime_field(item.get('updated_at')),
        )

    @staticmethod
    def _source_from_payload(item: dict) -> RequirementRegulatorySourceBridgeItem:
        return RequirementRegulatorySourceBridgeItem(
            id=int(item.get('id') or 0),
            framework=str(item.get('framework') or ''),
            code=str(item.get('code') or ''),
            title=str(item.get('title') or ''),
            authority=str(item.get('authority') or ''),
            citation=str(item.get('citation') or ''),
            url=str(item.get('url') or ''),
            source_type=str(item.get('source_type') or ''),
        )

    @staticmethod
    def _authenticated_request(request, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        tenant_id = getattr(getattr(user, 'tenant', None), 'id', None)
        if not user_id or not tenant_id:
            raise RuntimeError('Requirement-Rust-Bridge braucht authentifizierten Tenant-Kontext.')

        rust_request = Request(url)
        rust_request.add_header('Accept', 'application/json')
        rust_request.add_header('X-ISCY-Tenant-ID', str(tenant_id))
        rust_request.add_header('X-ISCY-User-ID', str(user_id))
        user_email = (getattr(user, 'email', '') or '').strip()
        if user_email:
            rust_request.add_header('X-ISCY-User-Email', user_email)
        return rust_request

    @staticmethod
    def _date_field(value) -> date | None:
        value = str(value or '').strip()
        if not value:
            return None
        return date.fromisoformat(value[:10])

    @staticmethod
    def _datetime_field(value) -> datetime | None:
        value = str(value or '').strip()
        if not value:
            return None
        return datetime.fromisoformat(value.replace('Z', '+00:00'))


class RequirementBridge:
    @staticmethod
    def fetch_library(request):
        backend = str(getattr(settings, 'REQUIREMENTS_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not RequirementRustClient._base_url():
            if RequirementBridge._strict_rust_mode():
                raise RuntimeError('Rust requirements backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return RequirementRustClient.fetch_library(request)
        except Exception as exc:
            if RequirementBridge._strict_rust_mode():
                raise RuntimeError('Rust requirements backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
