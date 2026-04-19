import json
from dataclasses import dataclass
from urllib.request import Request, urlopen

from django.conf import settings


@dataclass(frozen=True)
class ProductSecurityRelatedRef:
    id: int | None
    name: str

    @property
    def pk(self) -> int | None:
        return self.id

    @property
    def title(self) -> str:
        return self.name

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
class ProductSecurityReleaseItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    version: str
    status: str
    status_label: str
    release_date: str | None
    support_end_date: str | None
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityComponentItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    supplier: ProductSecurityRelatedRef | None
    supplier_id: int | None
    name: str
    component_type: str
    component_type_label: str
    version: str
    is_open_source: bool
    has_sbom: bool
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_component_type_display(self) -> str:
        return self.component_type_label


@dataclass(frozen=True)
class ProductSecurityThreatModelItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    release: ProductSecurityRelatedRef | None
    release_id: int | None
    name: str
    methodology: str
    summary: str
    status: str
    status_label: str
    scenarios: ProductSecurityRelatedCount
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityTaraItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    release: ProductSecurityRelatedRef | None
    release_id: int | None
    scenario: ProductSecurityRelatedRef | None
    scenario_id: int | None
    name: str
    summary: str
    attack_feasibility: int
    impact_score: int
    risk_score: int
    status: str
    status_label: str
    treatment_decision: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityVulnerabilityItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    release: ProductSecurityRelatedRef | None
    release_id: int | None
    component: ProductSecurityRelatedRef | None
    component_id: int | None
    title: str
    cve: str
    severity: str
    severity_label: str
    status: str
    status_label: str
    remediation_due: str | None
    summary: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_severity_display(self) -> str:
        return self.severity_label

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityAiSystemItem:
    id: int
    tenant: object
    tenant_id: int
    product: ProductSecurityRelatedRef | None
    product_id: int | None
    name: str
    use_case: str
    provider: str
    risk_classification: str
    risk_classification_label: str
    in_scope: bool
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_risk_classification_display(self) -> str:
        return self.risk_classification_label


@dataclass(frozen=True)
class ProductSecurityPsirtCaseItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    release: ProductSecurityRelatedRef | None
    release_id: int | None
    vulnerability: ProductSecurityRelatedRef | None
    vulnerability_id: int | None
    case_id: str
    title: str
    severity: str
    severity_label: str
    status: str
    status_label: str
    disclosure_due: str | None
    summary: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_severity_display(self) -> str:
        return self.severity_label

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityAdvisoryItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    release: ProductSecurityRelatedRef | None
    release_id: int | None
    psirt_case: ProductSecurityRelatedRef | None
    psirt_case_id: int | None
    advisory_id: str
    title: str
    status: str
    status_label: str
    published_on: str | None
    summary: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityRoadmapItem:
    id: int
    tenant: object
    tenant_id: int
    product_id: int
    title: str
    summary: str
    generated_from_snapshot_id: int | None
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id


@dataclass(frozen=True)
class ProductSecurityRoadmapTaskItem:
    id: int
    tenant: object
    tenant_id: int
    roadmap_id: int
    related_release: ProductSecurityRelatedRef | None
    related_release_id: int | None
    related_vulnerability: ProductSecurityRelatedRef | None
    related_vulnerability_id: int | None
    phase: str
    phase_label: str
    title: str
    description: str
    priority: str
    owner_role: str
    due_in_days: int
    dependency_text: str
    status: str
    status_label: str
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_phase_display(self) -> str:
        return self.phase_label

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class ProductSecurityOverviewBridgeResult:
    products: list[ProductSecurityProductListItem]
    snapshots: list[ProductSecuritySnapshotListItem]
    matrix: dict
    posture: dict


@dataclass(frozen=True)
class ProductSecurityDetailBridgeResult:
    product: ProductSecurityProductListItem
    releases: list[ProductSecurityReleaseItem]
    components: list[ProductSecurityComponentItem]
    threat_models: list[ProductSecurityThreatModelItem]
    threat_scenarios: int
    taras: list[ProductSecurityTaraItem]
    vulnerabilities: list[ProductSecurityVulnerabilityItem]
    ai_systems: list[ProductSecurityAiSystemItem]
    psirt_cases: list[ProductSecurityPsirtCaseItem]
    advisories: list[ProductSecurityAdvisoryItem]
    snapshot: ProductSecuritySnapshotListItem | None
    roadmap: ProductSecurityRoadmapItem | None
    roadmap_tasks: list[ProductSecurityRoadmapTaskItem]


@dataclass(frozen=True)
class ProductSecurityRoadmapBridgeResult:
    product: ProductSecurityProductListItem
    roadmap: ProductSecurityRoadmapItem
    tasks: list[ProductSecurityRoadmapTaskItem]
    snapshot: ProductSecuritySnapshotListItem | None


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
    def fetch_detail(request, tenant, product_id: int, timeout: int = 8) -> ProductSecurityDetailBridgeResult:
        base = ProductSecurityRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ProductSecurityRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/product-security/products/{int(product_id)}',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        product_payload = payload.get('product')
        if not isinstance(product_payload, dict):
            raise RuntimeError('Rust-Product-Security-Detail enthaelt kein Produkt.')

        product = ProductSecurityRustClient._product_from_payload(product_payload, tenant)
        if product.tenant_id != int(tenant.id) or product.id != int(product_id):
            raise RuntimeError('Rust-Product-Security-Detail gehoert nicht zum angefragten Produkt.')

        snapshot_payload = payload.get('snapshot')
        roadmap_payload = payload.get('roadmap')
        return ProductSecurityDetailBridgeResult(
            product=product,
            releases=ProductSecurityRustClient._items(payload, 'releases', tenant, ProductSecurityRustClient._release_from_payload),
            components=ProductSecurityRustClient._items(payload, 'components', tenant, ProductSecurityRustClient._component_from_payload),
            threat_models=ProductSecurityRustClient._items(payload, 'threat_models', tenant, ProductSecurityRustClient._threat_model_from_payload),
            threat_scenarios=ProductSecurityRustClient._int_field(payload, 'threat_scenarios'),
            taras=ProductSecurityRustClient._items(payload, 'taras', tenant, ProductSecurityRustClient._tara_from_payload),
            vulnerabilities=ProductSecurityRustClient._items(payload, 'vulnerabilities', tenant, ProductSecurityRustClient._vulnerability_from_payload),
            ai_systems=ProductSecurityRustClient._items(payload, 'ai_systems', tenant, ProductSecurityRustClient._ai_system_from_payload),
            psirt_cases=ProductSecurityRustClient._items(payload, 'psirt_cases', tenant, ProductSecurityRustClient._psirt_case_from_payload),
            advisories=ProductSecurityRustClient._items(payload, 'advisories', tenant, ProductSecurityRustClient._advisory_from_payload),
            snapshot=ProductSecurityRustClient._snapshot_from_payload(snapshot_payload, tenant) if isinstance(snapshot_payload, dict) else None,
            roadmap=ProductSecurityRustClient._roadmap_from_payload(roadmap_payload, tenant) if isinstance(roadmap_payload, dict) else None,
            roadmap_tasks=ProductSecurityRustClient._items(payload, 'roadmap_tasks', tenant, ProductSecurityRustClient._roadmap_task_from_payload),
        )

    @staticmethod
    def fetch_roadmap(request, tenant, product_id: int, timeout: int = 8) -> ProductSecurityRoadmapBridgeResult:
        base = ProductSecurityRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ProductSecurityRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/product-security/products/{int(product_id)}/roadmap',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        product_payload = payload.get('product')
        roadmap_payload = payload.get('roadmap')
        if not isinstance(product_payload, dict) or not isinstance(roadmap_payload, dict):
            raise RuntimeError('Rust-Product-Security-Roadmap enthaelt kein Produkt oder keine Roadmap.')

        product = ProductSecurityRustClient._product_from_payload(product_payload, tenant)
        if product.tenant_id != int(tenant.id) or product.id != int(product_id):
            raise RuntimeError('Rust-Product-Security-Roadmap gehoert nicht zum angefragten Produkt.')

        snapshot_payload = payload.get('snapshot')
        return ProductSecurityRoadmapBridgeResult(
            product=product,
            roadmap=ProductSecurityRustClient._roadmap_from_payload(roadmap_payload, tenant),
            tasks=ProductSecurityRustClient._items(payload, 'tasks', tenant, ProductSecurityRustClient._roadmap_task_from_payload),
            snapshot=ProductSecurityRustClient._snapshot_from_payload(snapshot_payload, tenant) if isinstance(snapshot_payload, dict) else None,
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
    def _release_from_payload(item: dict, tenant) -> ProductSecurityReleaseItem:
        return ProductSecurityReleaseItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            version=str(item.get('version') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            release_date=ProductSecurityRustClient._optional_str_field(item, 'release_date'),
            support_end_date=ProductSecurityRustClient._optional_str_field(item, 'support_end_date'),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _component_from_payload(item: dict, tenant) -> ProductSecurityComponentItem:
        supplier_id = ProductSecurityRustClient._optional_int_field(item, 'supplier_id')
        supplier_name = str(item.get('supplier_name') or '').strip()
        return ProductSecurityComponentItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            supplier=ProductSecurityRelatedRef(supplier_id, supplier_name) if supplier_name else None,
            supplier_id=supplier_id,
            name=str(item.get('name') or ''),
            component_type=str(item.get('component_type') or ''),
            component_type_label=str(item.get('component_type_label') or item.get('component_type') or ''),
            version=str(item.get('version') or ''),
            is_open_source=bool(item.get('is_open_source')),
            has_sbom=bool(item.get('has_sbom')),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _threat_model_from_payload(item: dict, tenant) -> ProductSecurityThreatModelItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'release_id')
        release_version = str(item.get('release_version') or '').strip()
        return ProductSecurityThreatModelItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            release_id=release_id,
            name=str(item.get('name') or ''),
            methodology=str(item.get('methodology') or ''),
            summary=str(item.get('summary') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            scenarios=ProductSecurityRelatedCount(ProductSecurityRustClient._int_field(item, 'scenario_count')),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _tara_from_payload(item: dict, tenant) -> ProductSecurityTaraItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'release_id')
        release_version = str(item.get('release_version') or '').strip()
        scenario_id = ProductSecurityRustClient._optional_int_field(item, 'scenario_id')
        scenario_title = str(item.get('scenario_title') or '').strip()
        return ProductSecurityTaraItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            release_id=release_id,
            scenario=ProductSecurityRelatedRef(scenario_id, scenario_title) if scenario_title else None,
            scenario_id=scenario_id,
            name=str(item.get('name') or ''),
            summary=str(item.get('summary') or ''),
            attack_feasibility=ProductSecurityRustClient._int_field(item, 'attack_feasibility'),
            impact_score=ProductSecurityRustClient._int_field(item, 'impact_score'),
            risk_score=ProductSecurityRustClient._int_field(item, 'risk_score'),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            treatment_decision=str(item.get('treatment_decision') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _vulnerability_from_payload(item: dict, tenant) -> ProductSecurityVulnerabilityItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'release_id')
        release_version = str(item.get('release_version') or '').strip()
        component_id = ProductSecurityRustClient._optional_int_field(item, 'component_id')
        component_name = str(item.get('component_name') or '').strip()
        return ProductSecurityVulnerabilityItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            release_id=release_id,
            component=ProductSecurityRelatedRef(component_id, component_name) if component_name else None,
            component_id=component_id,
            title=str(item.get('title') or ''),
            cve=str(item.get('cve') or ''),
            severity=str(item.get('severity') or ''),
            severity_label=str(item.get('severity_label') or item.get('severity') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            remediation_due=ProductSecurityRustClient._optional_str_field(item, 'remediation_due'),
            summary=str(item.get('summary') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _ai_system_from_payload(item: dict, tenant) -> ProductSecurityAiSystemItem:
        product_id = ProductSecurityRustClient._optional_int_field(item, 'product_id')
        product_name = str(item.get('product_name') or '').strip()
        return ProductSecurityAiSystemItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product=ProductSecurityRelatedRef(product_id, product_name) if product_name else None,
            product_id=product_id,
            name=str(item.get('name') or ''),
            use_case=str(item.get('use_case') or ''),
            provider=str(item.get('provider') or ''),
            risk_classification=str(item.get('risk_classification') or ''),
            risk_classification_label=str(item.get('risk_classification_label') or item.get('risk_classification') or ''),
            in_scope=bool(item.get('in_scope')),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _psirt_case_from_payload(item: dict, tenant) -> ProductSecurityPsirtCaseItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'release_id')
        release_version = str(item.get('release_version') or '').strip()
        vulnerability_id = ProductSecurityRustClient._optional_int_field(item, 'vulnerability_id')
        vulnerability_title = str(item.get('vulnerability_title') or '').strip()
        return ProductSecurityPsirtCaseItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            release_id=release_id,
            vulnerability=ProductSecurityRelatedRef(vulnerability_id, vulnerability_title) if vulnerability_title else None,
            vulnerability_id=vulnerability_id,
            case_id=str(item.get('case_id') or ''),
            title=str(item.get('title') or ''),
            severity=str(item.get('severity') or ''),
            severity_label=str(item.get('severity_label') or item.get('severity') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            disclosure_due=ProductSecurityRustClient._optional_str_field(item, 'disclosure_due'),
            summary=str(item.get('summary') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _advisory_from_payload(item: dict, tenant) -> ProductSecurityAdvisoryItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'release_id')
        release_version = str(item.get('release_version') or '').strip()
        psirt_case_id = ProductSecurityRustClient._optional_int_field(item, 'psirt_case_id')
        psirt_case_identifier = str(item.get('psirt_case_identifier') or '').strip()
        return ProductSecurityAdvisoryItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            release_id=release_id,
            psirt_case=ProductSecurityRelatedRef(psirt_case_id, psirt_case_identifier) if psirt_case_identifier else None,
            psirt_case_id=psirt_case_id,
            advisory_id=str(item.get('advisory_id') or ''),
            title=str(item.get('title') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            published_on=ProductSecurityRustClient._optional_str_field(item, 'published_on'),
            summary=str(item.get('summary') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _roadmap_from_payload(item: dict, tenant) -> ProductSecurityRoadmapItem:
        return ProductSecurityRoadmapItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            product_id=ProductSecurityRustClient._int_field(item, 'product_id'),
            title=str(item.get('title') or ''),
            summary=str(item.get('summary') or ''),
            generated_from_snapshot_id=ProductSecurityRustClient._optional_int_field(item, 'generated_from_snapshot_id'),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _roadmap_task_from_payload(item: dict, tenant) -> ProductSecurityRoadmapTaskItem:
        release_id = ProductSecurityRustClient._optional_int_field(item, 'related_release_id')
        release_version = str(item.get('related_release_version') or '').strip()
        vulnerability_id = ProductSecurityRustClient._optional_int_field(item, 'related_vulnerability_id')
        vulnerability_title = str(item.get('related_vulnerability_title') or '').strip()
        return ProductSecurityRoadmapTaskItem(
            id=ProductSecurityRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProductSecurityRustClient._int_field(item, 'tenant_id'),
            roadmap_id=ProductSecurityRustClient._int_field(item, 'roadmap_id'),
            related_release=ProductSecurityRelatedRef(release_id, release_version) if release_version else None,
            related_release_id=release_id,
            related_vulnerability=ProductSecurityRelatedRef(vulnerability_id, vulnerability_title) if vulnerability_title else None,
            related_vulnerability_id=vulnerability_id,
            phase=str(item.get('phase') or ''),
            phase_label=str(item.get('phase_label') or item.get('phase') or ''),
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            priority=str(item.get('priority') or ''),
            owner_role=str(item.get('owner_role') or ''),
            due_in_days=ProductSecurityRustClient._int_field(item, 'due_in_days'),
            dependency_text=str(item.get('dependency_text') or ''),
            status=str(item.get('status') or ''),
            status_label=str(item.get('status_label') or item.get('status') or ''),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _items(payload: dict, key: str, tenant, parser):
        return [
            parser(item, tenant)
            for item in payload.get(key, [])
            if isinstance(item, dict)
        ]

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

    @staticmethod
    def _optional_str_field(payload: dict, key: str) -> str | None:
        value = payload.get(key)
        if value in (None, ''):
            return None
        return str(value)


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
    def fetch_detail(request, tenant, product_id: int):
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
            return ProductSecurityRustClient.fetch_detail(request, tenant, product_id)
        except Exception as exc:
            if ProductSecurityBridge._strict_rust_mode():
                raise RuntimeError('Rust product security backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def fetch_roadmap(request, tenant, product_id: int):
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
            return ProductSecurityRustClient.fetch_roadmap(request, tenant, product_id)
        except Exception as exc:
            if ProductSecurityBridge._strict_rust_mode():
                raise RuntimeError('Rust product security backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
