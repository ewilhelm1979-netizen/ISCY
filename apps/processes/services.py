"""F05: 10-Dimensionen-Bewertungslogik fuer Prozesse/Kontrollen.

Leitet aus den Boolean-Feldern des Process-Models automatisch einen
Reifegradstatus und eine Gap-Indikation ab. Die 10 Dimensionen aus
der Projektdokumentation:
  1. dokumentiert
  2. genehmigt (approved)
  3. kommuniziert
  4. implementiert
  5. operativ wirksam (effective)
  6. evidenzbasiert (evidenced)
  7. Verantwortlichkeit zugewiesen (owner)
  8. reviewed (reviewed_at)
  9. versioniert -> hier: reviewed_at Datum vorhanden
  10. historisiert -> hier: Change-Log Eintraege (ueber AuditLog)

Fehlende Evidenzen duerfen die Wirksamkeit nicht automatisch widerlegen,
senken aber den Nachweisstatus.
"""

import json
from dataclasses import dataclass
from datetime import date
from typing import List, Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from django.conf import settings
from apps.processes.models import Process


STATUS_LABELS = dict(Process.Status.choices)


@dataclass(frozen=True)
class ProcessRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ProcessBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    business_unit: ProcessRelatedRef | None
    business_unit_id: int | None
    owner: ProcessRelatedRef | None
    owner_id: int | None
    name: str
    scope: str
    description: str
    status: str
    status_label: str
    documented: bool
    approved: bool
    communicated: bool
    implemented: bool
    effective: bool
    evidenced: bool
    reviewed_at: date | None
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label or STATUS_LABELS.get(self.status, self.status)


class ProcessRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_processes(request, tenant, timeout: int = 8) -> list[ProcessBridgeItem]:
        base = ProcessRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ProcessRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/processes',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = ProcessRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Prozessliste gehoert nicht zum angefragten Tenant.')

        return [
            ProcessRustClient._process_from_payload(item, tenant)
            for item in payload.get('processes', [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def fetch_process_detail(request, tenant, process_id: int, timeout: int = 8):
        base = ProcessRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = ProcessRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/processes/{int(process_id)}',
        )
        try:
            with urlopen(rust_request, timeout=timeout) as response:
                payload = json.loads(response.read().decode('utf-8'))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise

        process = payload.get('process') or {}
        if not isinstance(process, dict):
            raise RuntimeError('Rust-Prozessdetail hat kein process-Objekt geliefert.')
        process_tenant_id = ProcessRustClient._int_field(process, 'tenant_id')
        if process_tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Prozessdetail gehoert nicht zum angefragten Tenant.')
        return ProcessRustClient._process_from_payload(process, tenant)

    @staticmethod
    def _process_from_payload(item: dict, tenant) -> ProcessBridgeItem:
        business_unit_id = ProcessRustClient._optional_int_field(item, 'business_unit_id')
        business_unit_name = str(item.get('business_unit_name') or '').strip()
        owner_id = ProcessRustClient._optional_int_field(item, 'owner_id')
        owner_display = str(item.get('owner_display') or '').strip()
        status = str(item.get('status') or Process.Status.MISSING)
        return ProcessBridgeItem(
            id=ProcessRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=ProcessRustClient._int_field(item, 'tenant_id'),
            business_unit=ProcessRelatedRef(business_unit_id, business_unit_name) if business_unit_name else None,
            business_unit_id=business_unit_id,
            owner=ProcessRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            name=str(item.get('name') or ''),
            scope=str(item.get('scope') or ''),
            description=str(item.get('description') or ''),
            status=status,
            status_label=str(item.get('status_label') or STATUS_LABELS.get(status, status)),
            documented=bool(item.get('documented')),
            approved=bool(item.get('approved')),
            communicated=bool(item.get('communicated')),
            implemented=bool(item.get('implemented')),
            effective=bool(item.get('effective')),
            evidenced=bool(item.get('evidenced')),
            reviewed_at=ProcessRustClient._date_field(item, 'reviewed_at'),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Process-Rust-Bridge braucht einen authentifizierten User.')

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
    def _date_field(payload: dict, key: str) -> date | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        return date.fromisoformat(value[:10])


class ProcessRegisterBridge:
    @staticmethod
    def fetch_list(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'PROCESS_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not ProcessRustClient._base_url():
            if ProcessRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust process register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return ProcessRustClient.fetch_processes(request, tenant)
        except Exception as exc:
            if ProcessRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust process register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def fetch_detail(request, tenant, process_id: int):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'PROCESS_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not ProcessRustClient._base_url():
            if ProcessRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust process register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return ProcessRustClient.fetch_process_detail(request, tenant, process_id)
        except Exception as exc:
            if ProcessRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust process register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))


@dataclass
class DimensionResult:
    name: str
    fulfilled: bool
    weight: int = 1


@dataclass
class ProcessMaturityResult:
    process: Process
    dimensions: List[DimensionResult]
    score_percent: int
    maturity_label: str
    gap_level: str
    is_auditable: bool
    explanation: str


class ProcessMaturityService:

    @staticmethod
    def assess(process: Process) -> ProcessMaturityResult:
        """Bewertet einen Prozess anhand aller 10 Dimensionen."""
        has_owner = process.owner_id is not None
        has_review = process.reviewed_at is not None

        dimensions = [
            DimensionResult('Dokumentiert', process.documented, weight=2),
            DimensionResult('Genehmigt', process.approved, weight=1),
            DimensionResult('Kommuniziert', process.communicated, weight=1),
            DimensionResult('Implementiert', process.implemented, weight=2),
            DimensionResult('Operativ wirksam', process.effective, weight=2),
            DimensionResult('Evidenzbasiert', process.evidenced, weight=2),
            DimensionResult('Verantwortlichkeit zugewiesen', has_owner, weight=1),
            DimensionResult('Reviewed', has_review, weight=1),
            # Versioniert und historisiert werden ueber reviewed_at + AuditLog abgeleitet
            DimensionResult('Versioniert', has_review and process.documented, weight=1),
            DimensionResult('Historisiert', has_review, weight=1),
        ]

        max_score = sum(d.weight for d in dimensions)
        raw_score = sum(d.weight for d in dimensions if d.fulfilled)
        percent = int((raw_score / max_score) * 100) if max_score else 0

        # Fachliche Trennung: 'fachlich vorhanden' vs 'auditierbar nachweisbar'
        is_functionally_present = process.implemented or process.effective
        is_auditable = (
            process.documented
            and process.evidenced
            and has_owner
            and has_review
        )

        if percent >= 80:
            maturity, gap = 'Fortgeschritten / auditnah', 'LOW'
        elif percent >= 60:
            maturity, gap = 'Brauchbare Readiness', 'LOW'
        elif percent >= 40:
            maturity, gap = 'Grundlagen vorhanden', 'MEDIUM'
        elif percent >= 20:
            maturity, gap = 'Sehr niedriger Reifegrad', 'HIGH'
        else:
            maturity, gap = 'Kritisch', 'CRITICAL'

        # Erklarung
        missing = [d.name for d in dimensions if not d.fulfilled]
        if not missing:
            explanation = 'Alle Dimensionen sind erfuellt. Prozess ist auditnah.'
        elif is_functionally_present and not is_auditable:
            explanation = f'Prozess ist fachlich vorhanden, aber nicht auditierbar nachweisbar. Fehlend: {", ".join(missing)}.'
        else:
            explanation = f'Fehlende Dimensionen: {", ".join(missing)}.'

        return ProcessMaturityResult(
            process=process,
            dimensions=dimensions,
            score_percent=percent,
            maturity_label=maturity,
            gap_level=gap,
            is_auditable=is_auditable,
            explanation=explanation,
        )

    @staticmethod
    def assess_all(tenant) -> List[ProcessMaturityResult]:
        """Bewertet alle Prozesse eines Tenants."""
        processes = Process.objects.filter(tenant=tenant).select_related('owner')
        return [ProcessMaturityService.assess(p) for p in processes]

    @staticmethod
    def tenant_summary(tenant) -> dict:
        """Zusammenfassung der Reifegradverteilung fuer ein Tenant."""
        results = ProcessMaturityService.assess_all(tenant)
        if not results:
            return {'total': 0, 'average_percent': 0, 'auditable_count': 0, 'gap_distribution': {}}

        total = len(results)
        avg = int(sum(r.score_percent for r in results) / total) if total else 0
        auditable = sum(1 for r in results if r.is_auditable)
        gap_dist = {}
        for r in results:
            gap_dist[r.gap_level] = gap_dist.get(r.gap_level, 0) + 1

        return {
            'total': total,
            'average_percent': avg,
            'auditable_count': auditable,
            'auditable_percent': int((auditable / total) * 100) if total else 0,
            'gap_distribution': gap_dist,
        }
