import json
from dataclasses import dataclass
from datetime import date, datetime
from urllib.request import Request, urlopen

from django.conf import settings

from apps.assessments.models import ApplicabilityAssessment, Assessment, Measure


@dataclass(frozen=True)
class AssessmentRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class AssessmentRequirementRef:
    id: int
    framework: str
    code: str
    title: str

    def __str__(self) -> str:
        return f'{self.framework} - {self.code}'


@dataclass(frozen=True)
class ApplicabilityBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    tenant_name: str
    sector: str
    company_size: str
    critical_services: str
    supply_chain_role: str
    status: str
    status_label: str
    reasoning: str
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class AssessmentBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    process: AssessmentRelatedRef
    process_id: int
    requirement: AssessmentRequirementRef
    requirement_id: int
    owner: AssessmentRelatedRef | None
    owner_id: int | None
    status: str
    status_label: str
    score: int
    notes: str
    evidence_summary: str
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass(frozen=True)
class MeasureBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    assessment: AssessmentRelatedRef | None
    assessment_id: int | None
    owner: AssessmentRelatedRef | None
    owner_id: int | None
    title: str
    description: str
    priority: str
    priority_label: str
    status: str
    status_label: str
    due_date: date | None
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_priority_display(self) -> str:
        return self.priority_label

    def get_status_display(self) -> str:
        return self.status_label


class AssessmentRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_applicability(request, tenant, timeout: int = 8) -> list[ApplicabilityBridgeItem]:
        payload = AssessmentRustClient._fetch_items(
            request,
            tenant,
            '/api/v1/assessments/applicability',
            timeout=timeout,
        )
        return [
            AssessmentRustClient._applicability_from_payload(item, tenant)
            for item in payload
            if isinstance(item, dict)
        ]

    @staticmethod
    def fetch_assessments(request, tenant, timeout: int = 8) -> list[AssessmentBridgeItem]:
        payload = AssessmentRustClient._fetch_items(
            request,
            tenant,
            '/api/v1/assessments',
            timeout=timeout,
        )
        return [
            AssessmentRustClient._assessment_from_payload(item, tenant)
            for item in payload
            if isinstance(item, dict)
        ]

    @staticmethod
    def fetch_measures(request, tenant, timeout: int = 8) -> list[MeasureBridgeItem]:
        payload = AssessmentRustClient._fetch_items(
            request,
            tenant,
            '/api/v1/assessments/measures',
            timeout=timeout,
        )
        return [
            AssessmentRustClient._measure_from_payload(item, tenant)
            for item in payload
            if isinstance(item, dict)
        ]

    @staticmethod
    def _fetch_items(request, tenant, path: str, timeout: int) -> list[dict]:
        base = AssessmentRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = AssessmentRustClient._authenticated_request(request, tenant, f'{base}{path}')
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = AssessmentRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Assessmentliste gehoert nicht zum angefragten Tenant.')
        return payload.get('items', [])

    @staticmethod
    def _applicability_from_payload(item: dict, tenant) -> ApplicabilityBridgeItem:
        status = str(item.get('status') or ApplicabilityAssessment.Status.POSSIBLY_RELEVANT)
        return ApplicabilityBridgeItem(
            id=AssessmentRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=AssessmentRustClient._int_field(item, 'tenant_id'),
            tenant_name=str(item.get('tenant_name') or ''),
            sector=str(item.get('sector') or ''),
            company_size=str(item.get('company_size') or ''),
            critical_services=str(item.get('critical_services') or ''),
            supply_chain_role=str(item.get('supply_chain_role') or ''),
            status=status,
            status_label=str(item.get('status_label') or dict(ApplicabilityAssessment.Status.choices).get(status, status)),
            reasoning=str(item.get('reasoning') or ''),
            created_at=AssessmentRustClient._datetime_field(item, 'created_at'),
            updated_at=AssessmentRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _assessment_from_payload(item: dict, tenant) -> AssessmentBridgeItem:
        process_id = AssessmentRustClient._int_field(item, 'process_id')
        process_name = str(item.get('process_name') or '').strip()
        requirement = AssessmentRequirementRef(
            id=AssessmentRustClient._int_field(item, 'requirement_id'),
            framework=str(item.get('requirement_framework') or ''),
            code=str(item.get('requirement_code') or ''),
            title=str(item.get('requirement_title') or ''),
        )
        owner_id = AssessmentRustClient._optional_int_field(item, 'owner_id')
        owner_display = str(item.get('owner_display') or '').strip()
        status = str(item.get('status') or Assessment.Status.MISSING)
        return AssessmentBridgeItem(
            id=AssessmentRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=AssessmentRustClient._int_field(item, 'tenant_id'),
            process=AssessmentRelatedRef(process_id, process_name),
            process_id=process_id,
            requirement=requirement,
            requirement_id=requirement.id,
            owner=AssessmentRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            status=status,
            status_label=str(item.get('status_label') or dict(Assessment.Status.choices).get(status, status)),
            score=AssessmentRustClient._int_field(item, 'score'),
            notes=str(item.get('notes') or ''),
            evidence_summary=str(item.get('evidence_summary') or ''),
            created_at=AssessmentRustClient._datetime_field(item, 'created_at'),
            updated_at=AssessmentRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _measure_from_payload(item: dict, tenant) -> MeasureBridgeItem:
        assessment_id = AssessmentRustClient._optional_int_field(item, 'assessment_id')
        assessment_display = str(item.get('assessment_display') or '').strip()
        owner_id = AssessmentRustClient._optional_int_field(item, 'owner_id')
        owner_display = str(item.get('owner_display') or '').strip()
        priority = str(item.get('priority') or Measure.Priority.MEDIUM)
        status = str(item.get('status') or Measure.Status.OPEN)
        return MeasureBridgeItem(
            id=AssessmentRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=AssessmentRustClient._int_field(item, 'tenant_id'),
            assessment=AssessmentRelatedRef(assessment_id, assessment_display) if assessment_display else None,
            assessment_id=assessment_id,
            owner=AssessmentRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            priority=priority,
            priority_label=str(item.get('priority_label') or dict(Measure.Priority.choices).get(priority, priority)),
            status=status,
            status_label=str(item.get('status_label') or dict(Measure.Status.choices).get(status, status)),
            due_date=AssessmentRustClient._date_field(item, 'due_date'),
            created_at=AssessmentRustClient._datetime_field(item, 'created_at'),
            updated_at=AssessmentRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Assessment-Rust-Bridge braucht einen authentifizierten User.')

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
    def _datetime_field(payload: dict, key: str) -> datetime | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        return datetime.fromisoformat(value.replace('Z', '+00:00'))

    @staticmethod
    def _date_field(payload: dict, key: str) -> date | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        return date.fromisoformat(value[:10])


class AssessmentRegisterBridge:
    @staticmethod
    def fetch_applicability(request, tenant):
        if tenant is None:
            return None
        return AssessmentRegisterBridge._fetch(
            lambda: AssessmentRustClient.fetch_applicability(request, tenant),
        )

    @staticmethod
    def fetch_assessments(request, tenant):
        if tenant is None:
            return None
        return AssessmentRegisterBridge._fetch(
            lambda: AssessmentRustClient.fetch_assessments(request, tenant),
        )

    @staticmethod
    def fetch_measures(request, tenant):
        if tenant is None:
            return None
        return AssessmentRegisterBridge._fetch(
            lambda: AssessmentRustClient.fetch_measures(request, tenant),
        )

    @staticmethod
    def _fetch(fetcher):
        backend = str(getattr(settings, 'ASSESSMENT_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not AssessmentRustClient._base_url():
            if AssessmentRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust assessment register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return fetcher()
        except Exception as exc:
            if AssessmentRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust assessment register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
