import json
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings

from apps.evidence.models import EvidenceItem, RequirementEvidenceNeed
from apps.organizations.sector_catalog import get_sector_definition
from apps.requirements_app.models import Requirement


@dataclass(frozen=True)
class EvidenceRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class EvidenceMappingVersionRef:
    program_name: str
    framework: str
    version: str

    def __str__(self) -> str:
        return f'{self.program_name} {self.framework} {self.version}'


@dataclass(frozen=True)
class EvidenceRegulatorySourceRef:
    authority: str
    citation: str
    title: str

    def __str__(self) -> str:
        return ' - '.join(part for part in [self.authority, self.citation or self.title] if part)


@dataclass(frozen=True)
class EvidenceRequirementRef:
    id: int
    framework: str
    code: str
    title: str
    mapping_version: EvidenceMappingVersionRef | None
    primary_source: EvidenceRegulatorySourceRef | None

    def __str__(self) -> str:
        return f'{self.framework} - {self.code}'


@dataclass(frozen=True)
class EvidenceItemBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    session_id: int | None
    domain_id: int | None
    measure: EvidenceRelatedRef | None
    measure_id: int | None
    requirement: EvidenceRequirementRef | None
    requirement_id: int | None
    title: str
    description: str
    linked_requirement: str
    file: str | None
    status: str
    status_label: str
    owner: EvidenceRelatedRef | None
    owner_id: int | None
    review_notes: str
    reviewed_by: EvidenceRelatedRef | None
    reviewed_by_id: int | None
    reviewed_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    @property
    def requirement_display(self) -> str:
        if self.requirement:
            return f'{self.requirement.framework} {self.requirement.code} – {self.requirement.title}'
        return self.linked_requirement

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class RequirementEvidenceNeedBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    session_id: int | None
    requirement: EvidenceRequirementRef
    requirement_id: int
    title: str
    description: str
    is_mandatory: bool
    status: str
    status_label: str
    rationale: str
    covered_count: int
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    @property
    def requirement_mapping_version(self) -> str:
        requirement = self.requirement
        if not requirement or not requirement.mapping_version:
            return ''
        return f'{requirement.mapping_version.program_name} {requirement.framework} v{requirement.mapping_version.version}'

    @property
    def requirement_source_citation(self) -> str:
        requirement = self.requirement
        if not requirement or not requirement.primary_source:
            return ''
        source = requirement.primary_source
        parts = [source.authority, source.citation or source.title]
        return ' - '.join(part for part in parts if part)

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class EvidenceOverviewBridgeResult:
    evidence_items: list[EvidenceItemBridgeItem]
    evidence_needs: list[RequirementEvidenceNeedBridgeItem]
    need_summary: dict[str, int]


class EvidenceRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_overview(request, tenant, session_id: str | int | None = None, timeout: int = 8) -> EvidenceOverviewBridgeResult:
        base = EvidenceRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        url = f'{base}/api/v1/evidence'
        if session_id:
            url = f'{url}?{urlencode({"session_id": int(session_id)})}'
        rust_request = EvidenceRustClient._authenticated_request(request, tenant, url)
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = EvidenceRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Evidenzliste gehoert nicht zum angefragten Tenant.')

        return EvidenceOverviewBridgeResult(
            evidence_items=[
                EvidenceRustClient._evidence_item_from_payload(item, tenant)
                for item in payload.get('evidence_items', [])
                if isinstance(item, dict)
            ],
            evidence_needs=[
                EvidenceRustClient._evidence_need_from_payload(item, tenant)
                for item in payload.get('evidence_needs', [])
                if isinstance(item, dict)
            ],
            need_summary=EvidenceRustClient._need_summary_from_payload(payload.get('need_summary') or {}),
        )

    @staticmethod
    def sync_needs(request, tenant, session_id: int, timeout: int = 8) -> dict:
        base = EvidenceRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        payload = EvidenceRustClient._sync_payload()
        rust_request = EvidenceRustClient._authenticated_json_request(
            request,
            tenant,
            f'{base}/api/v1/evidence/sessions/{int(session_id)}/needs/sync',
            'POST',
            payload,
        )
        with urlopen(rust_request, timeout=timeout) as response:
            response_payload = json.loads(response.read().decode('utf-8'))

        result = response_payload.get('result') or response_payload
        result_session_id = EvidenceRustClient._int_field(result, 'session_id')
        if result_session_id != int(session_id):
            raise RuntimeError('Rust-Evidenzpflichten-Sync gehoert nicht zur angefragten Session.')
        return {
            'created': EvidenceRustClient._int_field(result, 'created'),
            'updated': EvidenceRustClient._int_field(result, 'updated'),
            'need_summary': EvidenceRustClient._need_summary_from_payload(result.get('need_summary') or {}),
        }

    @staticmethod
    def _sync_payload() -> dict:
        thresholds = getattr(settings, 'EVIDENCE_COVERAGE_THRESHOLDS', {'covered': 2, 'partial': 1})
        return {
            'covered_threshold': int(thresholds.get('covered', 2) or 2),
            'partial_threshold': int(thresholds.get('partial', 1) or 1),
        }

    @staticmethod
    def _evidence_item_from_payload(item: dict, tenant) -> EvidenceItemBridgeItem:
        measure_id = EvidenceRustClient._optional_int_field(item, 'measure_id')
        measure_title = str(item.get('measure_title') or '').strip()
        owner_id = EvidenceRustClient._optional_int_field(item, 'owner_id')
        owner_display = str(item.get('owner_display') or '').strip()
        reviewed_by_id = EvidenceRustClient._optional_int_field(item, 'reviewed_by_id')
        reviewed_by_display = str(item.get('reviewed_by_display') or '').strip()
        requirement = EvidenceRustClient._requirement_from_payload(item)
        return EvidenceItemBridgeItem(
            id=EvidenceRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=EvidenceRustClient._int_field(item, 'tenant_id'),
            session_id=EvidenceRustClient._optional_int_field(item, 'session_id'),
            domain_id=EvidenceRustClient._optional_int_field(item, 'domain_id'),
            measure=EvidenceRelatedRef(measure_id, measure_title) if measure_title else None,
            measure_id=measure_id,
            requirement=requirement,
            requirement_id=EvidenceRustClient._optional_int_field(item, 'requirement_id'),
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            linked_requirement=str(item.get('linked_requirement') or ''),
            file=EvidenceRustClient._optional_str_field(item, 'file_name'),
            status=str(item.get('status') or EvidenceItem.Status.DRAFT),
            status_label=str(item.get('status_label') or dict(EvidenceItem.Status.choices).get(item.get('status'), 'Entwurf')),
            owner=EvidenceRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            review_notes=str(item.get('review_notes') or ''),
            reviewed_by=EvidenceRelatedRef(reviewed_by_id, reviewed_by_display) if reviewed_by_display else None,
            reviewed_by_id=reviewed_by_id,
            reviewed_at=EvidenceRustClient._datetime_field(item, 'reviewed_at'),
            created_at=EvidenceRustClient._datetime_field(item, 'created_at'),
            updated_at=EvidenceRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _evidence_need_from_payload(item: dict, tenant) -> RequirementEvidenceNeedBridgeItem:
        requirement = EvidenceRustClient._requirement_from_payload(item)
        if requirement is None:
            raise RuntimeError('Rust-Evidenzpflicht hat keine Requirement-Daten geliefert.')
        return RequirementEvidenceNeedBridgeItem(
            id=EvidenceRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=EvidenceRustClient._int_field(item, 'tenant_id'),
            session_id=EvidenceRustClient._optional_int_field(item, 'session_id'),
            requirement=requirement,
            requirement_id=EvidenceRustClient._int_field(item, 'requirement_id'),
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            is_mandatory=bool(item.get('is_mandatory')),
            status=str(item.get('status') or RequirementEvidenceNeed.Status.OPEN),
            status_label=str(item.get('status_label') or dict(RequirementEvidenceNeed.Status.choices).get(item.get('status'), 'Offen')),
            rationale=str(item.get('rationale') or ''),
            covered_count=EvidenceRustClient._int_field(item, 'covered_count'),
            created_at=EvidenceRustClient._datetime_field(item, 'created_at'),
            updated_at=EvidenceRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _requirement_from_payload(item: dict) -> EvidenceRequirementRef | None:
        requirement_id = EvidenceRustClient._optional_int_field(item, 'requirement_id')
        framework = str(item.get('requirement_framework') or '').strip()
        code = str(item.get('requirement_code') or '').strip()
        title = str(item.get('requirement_title') or '').strip()
        if not requirement_id or not framework or not code:
            return None

        mapping_version = None
        mapping_program_name = str(item.get('mapping_program_name') or '').strip()
        mapping_version_value = str(item.get('mapping_version') or '').strip()
        if mapping_program_name and mapping_version_value:
            mapping_version = EvidenceMappingVersionRef(
                program_name=mapping_program_name,
                framework=framework,
                version=mapping_version_value,
            )

        primary_source = None
        source_authority = str(item.get('source_authority') or '').strip()
        source_citation = str(item.get('source_citation') or '').strip()
        source_title = str(item.get('source_title') or '').strip()
        if source_authority or source_citation or source_title:
            primary_source = EvidenceRegulatorySourceRef(
                authority=source_authority,
                citation=source_citation,
                title=source_title,
            )

        return EvidenceRequirementRef(
            id=requirement_id,
            framework=framework,
            code=code,
            title=title,
            mapping_version=mapping_version,
            primary_source=primary_source,
        )

    @staticmethod
    def _need_summary_from_payload(payload: dict) -> dict[str, int]:
        return {
            'open': int(payload.get('open') or 0),
            'partial': int(payload.get('partial') or 0),
            'covered': int(payload.get('covered') or 0),
        }

    @staticmethod
    def _authenticated_request(request, tenant, url: str, *, method: str = 'GET', data: bytes | None = None) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Evidence-Rust-Bridge braucht einen authentifizierten User.')

        rust_request = Request(url, data=data, method=method)
        rust_request.add_header('Accept', 'application/json')
        if data is not None:
            rust_request.add_header('Content-Type', 'application/json')
        rust_request.add_header('X-ISCY-Tenant-ID', str(tenant.id))
        rust_request.add_header('X-ISCY-User-ID', str(user_id))
        user_email = (getattr(user, 'email', '') or '').strip()
        if user_email:
            rust_request.add_header('X-ISCY-User-Email', user_email)
        return rust_request

    @staticmethod
    def _authenticated_json_request(request, tenant, url: str, method: str, payload: dict) -> Request:
        data = json.dumps(payload).encode('utf-8')
        return EvidenceRustClient._authenticated_request(request, tenant, url, method=method, data=data)

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
        value = str(payload.get(key) or '').strip()
        return value or None

    @staticmethod
    def _datetime_field(payload: dict, key: str) -> datetime | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        normalized = value.replace('Z', '+00:00')
        return datetime.fromisoformat(normalized)


class EvidenceRegisterBridge:
    @staticmethod
    def fetch_overview(request, tenant, session_id: str | int | None = None):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'EVIDENCE_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not EvidenceRustClient._base_url():
            if EvidenceRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust evidence register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return EvidenceRustClient.fetch_overview(request, tenant, session_id=session_id)
        except Exception as exc:
            if EvidenceRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust evidence register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def sync_needs_for_session(request, session):
        tenant = getattr(session, 'tenant', None)
        if tenant is None:
            return None

        backend = str(getattr(settings, 'EVIDENCE_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not EvidenceRustClient._base_url():
            if EvidenceRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust evidence register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return EvidenceRustClient.sync_needs(request, tenant, session.id)
        except Exception as exc:
            if EvidenceRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust evidence need sync backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))


class EvidenceNeedService:
    DOMAIN_KEYWORDS = {
        'GOV': ['governance', 'scope', 'policy', 'roles', 'management'],
        'PROC': ['asset', 'prozess', 'process', 'inventory', 'register'],
        'SUP': ['supplier', 'liefer', 'third'],
        'IAM': ['identity', 'access', 'iam', 'mfa', 'privileg'],
        'CLOUD': ['cloud', 'shared responsibility', 'saas', 'hosting'],
        'SDLC': ['development', 'sdlc', 'change', 'release', 'code'],
        'CYBER': ['patch', 'vulnerability', 'hardening', 'hygiene'],
        'CRYPTO': ['crypto', 'verschlüssel', 'key'],
        'PHYS': ['physical', 'facility', 'zugang'],
        'DETECT': ['logging', 'monitoring', 'detection', 'alarm'],
        'INC': ['incident', 'meldung', 'response'],
        'BCM': ['backup', 'recovery', 'bcm', 'restore'],
        'AWARE': ['awareness', 'training', 'schulung'],
        'DOC': ['document', 'review', 'policy', 'version'],
    }

    @staticmethod
    def get_sector_packages(tenant):
        sector = get_sector_definition(getattr(tenant, 'sector', None))
        packages = {'ALL'}
        if sector.code in {'DIGITAL_PROVIDERS', 'DIGITAL_INFRASTRUCTURE', 'ICT_SERVICE_MANAGEMENT', 'MSSP'}:
            packages.add('DIGITAL')
        if sector.code in {'BANKING', 'FINANCIAL_MARKET_INFRASTRUCTURE'}:
            packages.add('FINANCE')
        if sector.kritis_related or sector.code in {'ENERGY', 'TRANSPORT', 'HEALTH', 'DRINKING_WATER', 'WASTEWATER', 'PUBLIC_ADMINISTRATION'}:
            packages.add('CRITICAL_INFRA')
        return packages

    @staticmethod
    def requirement_relevant(requirement, tenant):
        pkg = (requirement.sector_package or '').strip().upper()
        if not pkg or pkg == 'ALL':
            return True
        return pkg in EvidenceNeedService.get_sector_packages(tenant)

    @staticmethod
    def sync_for_session(session):
        tenant = session.tenant
        # F12: Konfigurierbare Schwellen aus Settings
        thresholds = getattr(settings, 'EVIDENCE_COVERAGE_THRESHOLDS', {'covered': 2, 'partial': 1})
        covered_threshold = thresholds.get('covered', 2)
        partial_threshold = thresholds.get('partial', 1)

        created = 0
        updated = 0
        for requirement in Requirement.objects.filter(is_active=True).order_by('framework', 'code'):
            if not EvidenceNeedService.requirement_relevant(requirement, tenant):
                continue
            evidence_qs = EvidenceItem.objects.filter(tenant=tenant, requirement=requirement)
            covered_count = evidence_qs.count()
            if covered_count >= covered_threshold:
                status = RequirementEvidenceNeed.Status.COVERED
            elif covered_count >= partial_threshold:
                status = RequirementEvidenceNeed.Status.PARTIAL
            else:
                status = RequirementEvidenceNeed.Status.OPEN
            defaults = {
                'title': f'Nachweis für {requirement.framework} {requirement.code}',
                'description': EvidenceNeedService.requirement_description(requirement),
                'is_mandatory': requirement.evidence_required,
                'status': status,
                'rationale': EvidenceNeedService.requirement_rationale(requirement),
                'covered_count': covered_count,
            }
            obj, was_created = RequirementEvidenceNeed.objects.update_or_create(
                tenant=tenant,
                session=session,
                requirement=requirement,
                defaults=defaults,
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated

    @staticmethod
    def related_needs_for_measure(measure, limit=4):
        qs = RequirementEvidenceNeed.objects.filter(tenant=measure.session.tenant)
        if measure.session_id:
            qs = qs.filter(session=measure.session)
        if measure.domain_id:
            domain_code = measure.domain.code.upper()
            keywords = EvidenceNeedService.DOMAIN_KEYWORDS.get(domain_code, [])
            filtered = []
            for need in qs.select_related('requirement'):
                haystack = ' '.join([
                    need.requirement.domain or '',
                    need.requirement.title or '',
                    need.requirement.description or '',
                    need.title or '',
                    need.description or '',
                ]).lower()
                if any(keyword.lower() in haystack for keyword in keywords):
                    filtered.append(need)
            if filtered:
                return filtered[:limit]
        return list(qs.select_related('requirement').order_by('status', 'requirement__framework', 'requirement__code')[:limit])

    @staticmethod
    def measure_need_summary(measure):
        needs = EvidenceNeedService.related_needs_for_measure(measure, limit=6)
        summary = {
            'open': 0,
            'partial': 0,
            'covered': 0,
            'total': len(needs),
            'items': needs,
        }
        for need in needs:
            if need.status == RequirementEvidenceNeed.Status.OPEN:
                summary['open'] += 1
            elif need.status == RequirementEvidenceNeed.Status.PARTIAL:
                summary['partial'] += 1
            elif need.status == RequirementEvidenceNeed.Status.COVERED:
                summary['covered'] += 1
        return summary

    @staticmethod
    def requirement_description(requirement):
        parts = [requirement.evidence_guidance or requirement.description]
        if requirement.mapping_version:
            parts.append(f'Mapping-Version: {requirement.mapping_version.program_name} {requirement.framework} v{requirement.mapping_version.version}')
        if requirement.primary_source:
            citation = requirement.primary_source.citation or requirement.primary_source.title
            parts.append(f'Quelle: {requirement.primary_source.authority} - {citation}')
        return ' | '.join(part for part in parts if part)

    @staticmethod
    def requirement_rationale(requirement):
        parts = [requirement.evidence_examples or 'Evidenzen, Richtlinien, Screenshots, Freigaben oder Prüfprotokolle hinterlegen.']
        if requirement.legal_reference:
            parts.append(f'Referenz: {requirement.legal_reference}')
        if requirement.primary_source and requirement.primary_source.url:
            parts.append(f'Quelle: {requirement.primary_source.url}')
        return ' | '.join(part for part in parts if part)
