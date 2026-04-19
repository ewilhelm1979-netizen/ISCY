import json
from dataclasses import dataclass, field
from urllib.request import Request, urlopen

from django.conf import settings


class CatalogRelatedList:
    def __init__(self, items=None):
        self._items = list(items or [])

    def all(self):
        return list(self._items)

    def count(self):
        return len(self._items)

    def add(self, item):
        self._items.append(item)

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)


@dataclass(frozen=True)
class CatalogQuestionBridgeItem:
    id: int
    domain_id: int | None
    code: str
    text: str
    help_text: str
    why_it_matters: str
    question_kind: str
    question_kind_label: str
    wizard_step: str
    wizard_step_label: str
    weight: int
    is_required: bool
    applies_to_iso27001: bool
    applies_to_nis2: bool
    applies_to_cra: bool
    applies_to_ai_act: bool
    applies_to_iec62443: bool
    applies_to_iso_sae_21434: bool
    applies_to_product_security: bool
    sort_order: int
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_question_kind_display(self) -> str:
        return self.question_kind_label

    def get_wizard_step_display(self) -> str:
        return self.wizard_step_label


@dataclass
class CatalogDomainBridgeItem:
    id: int
    code: str
    name: str
    description: str
    weight: int
    sort_order: int
    question_count: int
    created_at: str
    updated_at: str
    questions: CatalogRelatedList = field(default_factory=CatalogRelatedList)

    @property
    def pk(self) -> int:
        return self.id

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class CatalogDomainLibraryBridgeResult:
    domains: list[CatalogDomainBridgeItem]
    question_count: int


class CatalogRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_domain_library(request, timeout: int = 8) -> CatalogDomainLibraryBridgeResult:
        base = CatalogRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = CatalogRustClient._authenticated_request(request, f'{base}/api/v1/catalog/domains')
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        domains = [
            CatalogRustClient._domain_from_payload(item)
            for item in payload.get('domains', [])
            if isinstance(item, dict)
        ]
        return CatalogDomainLibraryBridgeResult(
            domains=domains,
            question_count=int(payload.get('question_count') or 0),
        )

    @staticmethod
    def _domain_from_payload(item: dict) -> CatalogDomainBridgeItem:
        domain = CatalogDomainBridgeItem(
            id=int(item.get('id') or 0),
            code=str(item.get('code') or ''),
            name=str(item.get('name') or ''),
            description=str(item.get('description') or ''),
            weight=int(item.get('weight') or 0),
            sort_order=int(item.get('sort_order') or 0),
            question_count=int(item.get('question_count') or 0),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )
        for question_payload in item.get('questions', []):
            if isinstance(question_payload, dict):
                domain.questions.add(CatalogRustClient._question_from_payload(question_payload))
        return domain

    @staticmethod
    def _question_from_payload(item: dict) -> CatalogQuestionBridgeItem:
        return CatalogQuestionBridgeItem(
            id=int(item.get('id') or 0),
            domain_id=CatalogRustClient._optional_int(item.get('domain_id')),
            code=str(item.get('code') or ''),
            text=str(item.get('text') or ''),
            help_text=str(item.get('help_text') or ''),
            why_it_matters=str(item.get('why_it_matters') or ''),
            question_kind=str(item.get('question_kind') or ''),
            question_kind_label=str(item.get('question_kind_label') or ''),
            wizard_step=str(item.get('wizard_step') or ''),
            wizard_step_label=str(item.get('wizard_step_label') or ''),
            weight=int(item.get('weight') or 0),
            is_required=bool(item.get('is_required')),
            applies_to_iso27001=bool(item.get('applies_to_iso27001')),
            applies_to_nis2=bool(item.get('applies_to_nis2')),
            applies_to_cra=bool(item.get('applies_to_cra')),
            applies_to_ai_act=bool(item.get('applies_to_ai_act')),
            applies_to_iec62443=bool(item.get('applies_to_iec62443')),
            applies_to_iso_sae_21434=bool(item.get('applies_to_iso_sae_21434')),
            applies_to_product_security=bool(item.get('applies_to_product_security')),
            sort_order=int(item.get('sort_order') or 0),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        tenant_id = getattr(getattr(user, 'tenant', None), 'id', None)
        if not user_id or not tenant_id:
            raise RuntimeError('Catalog-Rust-Bridge braucht authentifizierten Tenant-Kontext.')

        rust_request = Request(url)
        rust_request.add_header('Accept', 'application/json')
        rust_request.add_header('X-ISCY-Tenant-ID', str(tenant_id))
        rust_request.add_header('X-ISCY-User-ID', str(user_id))
        user_email = (getattr(user, 'email', '') or '').strip()
        if user_email:
            rust_request.add_header('X-ISCY-User-Email', user_email)
        return rust_request

    @staticmethod
    def _optional_int(value) -> int | None:
        if value in (None, ''):
            return None
        return int(value)


class CatalogBridge:
    @staticmethod
    def fetch_domain_library(request):
        backend = str(getattr(settings, 'CATALOG_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not CatalogRustClient._base_url():
            if CatalogBridge._strict_rust_mode():
                raise RuntimeError('Rust catalog backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return CatalogRustClient.fetch_domain_library(request)
        except Exception as exc:
            if CatalogBridge._strict_rust_mode():
                raise RuntimeError('Rust catalog backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
