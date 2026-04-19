"""V20: Risk-Matrix-Service fuer 5x5 Heatmap."""
from collections import defaultdict
import json
from dataclasses import dataclass
from datetime import date, datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from django.conf import settings

from .models import Risk


IMPACT_LABELS = dict(Risk.IMPACT_CHOICES)
LIKELIHOOD_LABELS = dict(Risk.LIKELIHOOD_CHOICES)
STATUS_LABELS = dict(Risk.Status.choices)
TREATMENT_LABELS = dict(Risk.Treatment.choices)


@dataclass(frozen=True)
class RiskRelatedRef:
    id: int | None
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class RiskBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    category: RiskRelatedRef | None
    category_id: int | None
    process: RiskRelatedRef | None
    process_id: int | None
    asset: RiskRelatedRef | None
    asset_id: int | None
    owner: RiskRelatedRef | None
    owner_id: int | None
    title: str
    description: str
    threat: str
    vulnerability: str
    impact: int
    impact_label: str
    likelihood: int
    likelihood_label: str
    residual_impact: int | None
    residual_impact_label: str | None
    residual_likelihood: int | None
    residual_likelihood_label: str | None
    status: str
    status_label: str
    treatment_strategy: str
    treatment_strategy_label: str
    treatment_plan: str
    treatment_due_date: date | None
    accepted_by: RiskRelatedRef | None
    accepted_by_id: int | None
    accepted_at: datetime | None
    review_date: date | None
    created_at: str
    updated_at: str

    @property
    def pk(self) -> int:
        return self.id

    @property
    def score(self) -> int:
        return self.impact * self.likelihood

    @property
    def residual_score(self) -> int | None:
        if self.residual_impact and self.residual_likelihood:
            return self.residual_impact * self.residual_likelihood
        return None

    @property
    def risk_level(self) -> str:
        score = self.score
        if score >= 20:
            return 'CRITICAL'
        if score >= 12:
            return 'HIGH'
        if score >= 6:
            return 'MEDIUM'
        return 'LOW'

    @property
    def risk_level_label(self) -> str:
        return {'CRITICAL': 'Kritisch', 'HIGH': 'Hoch', 'MEDIUM': 'Mittel', 'LOW': 'Niedrig'}.get(
            self.risk_level,
            '–',
        )

    @property
    def severity(self) -> int:
        return self.impact

    def get_impact_display(self) -> str:
        return self.impact_label or IMPACT_LABELS.get(self.impact, str(self.impact))

    def get_likelihood_display(self) -> str:
        return self.likelihood_label or LIKELIHOOD_LABELS.get(self.likelihood, str(self.likelihood))

    def get_status_display(self) -> str:
        return self.status_label or STATUS_LABELS.get(self.status, self.status)

    def get_treatment_strategy_display(self) -> str:
        return self.treatment_strategy_label or TREATMENT_LABELS.get(self.treatment_strategy, self.treatment_strategy)


class RiskRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_risks(request, tenant, timeout: int = 8) -> list[RiskBridgeItem]:
        base = RiskRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RiskRustClient._authenticated_request(request, tenant, f'{base}/api/v1/risks')
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = RiskRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Risikoliste gehoert nicht zum angefragten Tenant.')

        return [
            RiskRustClient._risk_from_payload(item, tenant)
            for item in payload.get('risks', [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def fetch_risk_detail(request, tenant, risk_id: int, timeout: int = 8):
        base = RiskRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RiskRustClient._authenticated_request(request, tenant, f'{base}/api/v1/risks/{int(risk_id)}')
        try:
            with urlopen(rust_request, timeout=timeout) as response:
                payload = json.loads(response.read().decode('utf-8'))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise

        risk = payload.get('risk') or {}
        if not isinstance(risk, dict):
            raise RuntimeError('Rust-Risikodetail hat kein risk-Objekt geliefert.')
        risk_tenant_id = RiskRustClient._int_field(risk, 'tenant_id')
        if risk_tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Risikodetail gehoert nicht zum angefragten Tenant.')
        return RiskRustClient._risk_from_payload(risk, tenant)

    @staticmethod
    def create_risk(request, tenant, payload: dict, timeout: int = 8):
        base = RiskRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RiskRustClient._authenticated_json_request(
            request,
            tenant,
            f'{base}/api/v1/risks',
            'POST',
            payload,
        )
        with urlopen(rust_request, timeout=timeout) as response:
            response_payload = json.loads(response.read().decode('utf-8'))

        risk = response_payload.get('risk') or {}
        if not isinstance(risk, dict):
            raise RuntimeError('Rust-Risikoanlage hat kein risk-Objekt geliefert.')
        risk_tenant_id = RiskRustClient._int_field(risk, 'tenant_id')
        if risk_tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Risikoanlage gehoert nicht zum angefragten Tenant.')
        return RiskRustClient._risk_from_payload(risk, tenant)

    @staticmethod
    def update_risk(request, tenant, risk_id: int, payload: dict, timeout: int = 8):
        base = RiskRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RiskRustClient._authenticated_json_request(
            request,
            tenant,
            f'{base}/api/v1/risks/{int(risk_id)}',
            'PATCH',
            payload,
        )
        with urlopen(rust_request, timeout=timeout) as response:
            response_payload = json.loads(response.read().decode('utf-8'))

        risk = response_payload.get('risk') or {}
        if not isinstance(risk, dict):
            raise RuntimeError('Rust-Risikoaktualisierung hat kein risk-Objekt geliefert.')
        risk_tenant_id = RiskRustClient._int_field(risk, 'tenant_id')
        if risk_tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Risikoaktualisierung gehoert nicht zum angefragten Tenant.')
        return RiskRustClient._risk_from_payload(risk, tenant)

    @staticmethod
    def payload_from_form(form) -> dict:
        cleaned_data = form.cleaned_data

        def pk(field_name: str) -> int | None:
            value = cleaned_data.get(field_name)
            return getattr(value, 'pk', None) if value is not None else None

        def date_value(field_name: str) -> str | None:
            value = cleaned_data.get(field_name)
            return value.isoformat() if value else None

        return {
            'category_id': pk('category'),
            'process_id': pk('process'),
            'asset_id': pk('asset'),
            'owner_id': pk('owner'),
            'title': cleaned_data.get('title') or '',
            'description': cleaned_data.get('description') or '',
            'threat': cleaned_data.get('threat') or '',
            'vulnerability': cleaned_data.get('vulnerability') or '',
            'impact': cleaned_data.get('impact') or 3,
            'likelihood': cleaned_data.get('likelihood') or 3,
            'residual_impact': cleaned_data.get('residual_impact'),
            'residual_likelihood': cleaned_data.get('residual_likelihood'),
            'status': cleaned_data.get('status') or Risk.Status.IDENTIFIED,
            'treatment_strategy': cleaned_data.get('treatment_strategy') or '',
            'treatment_plan': cleaned_data.get('treatment_plan') or '',
            'treatment_due_date': date_value('treatment_due_date'),
            'review_date': date_value('review_date'),
        }

    @staticmethod
    def _risk_from_payload(item: dict, tenant) -> RiskBridgeItem:
        category_id = RiskRustClient._optional_int_field(item, 'category_id')
        process_id = RiskRustClient._optional_int_field(item, 'process_id')
        asset_id = RiskRustClient._optional_int_field(item, 'asset_id')
        owner_id = RiskRustClient._optional_int_field(item, 'owner_id')
        accepted_by_id = RiskRustClient._optional_int_field(item, 'accepted_by_id')
        category_name = str(item.get('category_name') or '').strip()
        process_name = str(item.get('process_name') or '').strip()
        asset_name = str(item.get('asset_name') or '').strip()
        owner_display = str(item.get('owner_display') or '').strip()
        accepted_by_display = str(item.get('accepted_by_display') or '').strip()
        impact = RiskRustClient._int_field(item, 'impact')
        likelihood = RiskRustClient._int_field(item, 'likelihood')
        status = str(item.get('status') or Risk.Status.IDENTIFIED)
        treatment_strategy = str(item.get('treatment_strategy') or '')
        return RiskBridgeItem(
            id=RiskRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=RiskRustClient._int_field(item, 'tenant_id'),
            category=RiskRelatedRef(category_id, category_name) if category_name else None,
            category_id=category_id,
            process=RiskRelatedRef(process_id, process_name) if process_name else None,
            process_id=process_id,
            asset=RiskRelatedRef(asset_id, asset_name) if asset_name else None,
            asset_id=asset_id,
            owner=RiskRelatedRef(owner_id, owner_display) if owner_display else None,
            owner_id=owner_id,
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            threat=str(item.get('threat') or ''),
            vulnerability=str(item.get('vulnerability') or ''),
            impact=impact,
            impact_label=str(item.get('impact_label') or IMPACT_LABELS.get(impact, impact)),
            likelihood=likelihood,
            likelihood_label=str(item.get('likelihood_label') or LIKELIHOOD_LABELS.get(likelihood, likelihood)),
            residual_impact=RiskRustClient._optional_int_field(item, 'residual_impact'),
            residual_impact_label=RiskRustClient._optional_str_field(item, 'residual_impact_label'),
            residual_likelihood=RiskRustClient._optional_int_field(item, 'residual_likelihood'),
            residual_likelihood_label=RiskRustClient._optional_str_field(item, 'residual_likelihood_label'),
            status=status,
            status_label=str(item.get('status_label') or STATUS_LABELS.get(status, status)),
            treatment_strategy=treatment_strategy,
            treatment_strategy_label=str(
                item.get('treatment_strategy_label') or TREATMENT_LABELS.get(treatment_strategy, treatment_strategy)
            ),
            treatment_plan=str(item.get('treatment_plan') or ''),
            treatment_due_date=RiskRustClient._date_field(item, 'treatment_due_date'),
            accepted_by=RiskRelatedRef(accepted_by_id, accepted_by_display) if accepted_by_display else None,
            accepted_by_id=accepted_by_id,
            accepted_at=RiskRustClient._datetime_field(item, 'accepted_at'),
            review_date=RiskRustClient._date_field(item, 'review_date'),
            created_at=str(item.get('created_at') or ''),
            updated_at=str(item.get('updated_at') or ''),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str, *, method: str = 'GET', data: bytes | None = None) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Risk-Rust-Bridge braucht einen authentifizierten User.')

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
        return RiskRustClient._authenticated_request(request, tenant, url, method=method, data=data)

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
    def _date_field(payload: dict, key: str) -> date | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        return date.fromisoformat(value[:10])

    @staticmethod
    def _datetime_field(payload: dict, key: str) -> datetime | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        normalized = value.replace('Z', '+00:00')
        return datetime.fromisoformat(normalized)


class RiskRegisterBridge:
    @staticmethod
    def fetch_list(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'RISK_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not RiskRustClient._base_url():
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return RiskRustClient.fetch_risks(request, tenant)
        except Exception as exc:
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def fetch_detail(request, tenant, risk_id: int):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'RISK_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not RiskRustClient._base_url():
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return RiskRustClient.fetch_risk_detail(request, tenant, risk_id)
        except Exception as exc:
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def create_from_form(request, tenant, form):
        if not RiskRegisterBridge._writes_enabled(tenant):
            return None

        payload = RiskRustClient.payload_from_form(form)
        try:
            return RiskRustClient.create_risk(request, tenant, payload)
        except Exception as exc:
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register write backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def update_from_form(request, tenant, risk_id: int, form):
        if not RiskRegisterBridge._writes_enabled(tenant):
            return None

        payload = RiskRustClient.payload_from_form(form)
        try:
            return RiskRustClient.update_risk(request, tenant, risk_id, payload)
        except Exception as exc:
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register write backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _writes_enabled(tenant) -> bool:
        if tenant is None:
            return False

        backend = str(getattr(settings, 'RISK_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return False

        if not RiskRustClient._base_url():
            if RiskRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust risk register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return False
        return True

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))


class RiskMatrixService:
    """Baut eine 5x5 Risikomatrix mit Faerbung und Risikozaehlung."""

    LEVEL_MAP = {
        (5, 5): 'critical', (5, 4): 'critical', (4, 5): 'critical',
        (5, 3): 'high', (4, 4): 'high', (3, 5): 'high', (4, 3): 'high', (3, 4): 'high',
        (5, 2): 'high', (2, 5): 'high',
        (5, 1): 'medium', (1, 5): 'medium', (4, 2): 'medium', (2, 4): 'medium',
        (3, 3): 'medium', (3, 2): 'medium', (2, 3): 'medium',
        (4, 1): 'medium', (1, 4): 'medium',
        (3, 1): 'low', (1, 3): 'low', (2, 2): 'low', (2, 1): 'low', (1, 2): 'low',
        (1, 1): 'low',
    }

    COLORS = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#f59e0b',
        'low': '#22c55e',
    }

    BG_COLORS = {
        'critical': '#fef2f2',
        'high': '#fff7ed',
        'medium': '#fffbeb',
        'low': '#f0fdf4',
    }

    @staticmethod
    def build_matrix(risks):
        """Baut die 5x5 Matrix aus einer QuerySet von Risks.
        Returns: list of rows (likelihood 5->1), each row = list of cells.
        """
        count_map = defaultdict(list)
        for risk in risks:
            count_map[(risk.impact, risk.likelihood)].append(risk)

        matrix = []
        for likelihood in range(5, 0, -1):
            row = []
            for impact in range(1, 6):
                level = RiskMatrixService.LEVEL_MAP.get((impact, likelihood), 'low')
                cell_risks = count_map.get((impact, likelihood), [])
                row.append({
                    'impact': impact,
                    'likelihood': likelihood,
                    'level': level,
                    'color': RiskMatrixService.COLORS[level],
                    'bg_color': RiskMatrixService.BG_COLORS[level],
                    'count': len(cell_risks),
                    'risks': cell_risks,
                    'score': impact * likelihood,
                })
            matrix.append({'likelihood': likelihood, 'cells': row})
        return matrix

    @staticmethod
    def summary(risks):
        """Zaehlt Risiken nach Level."""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for risk in risks:
            level = RiskMatrixService.LEVEL_MAP.get((risk.impact, risk.likelihood), 'low')
            summary[level] += 1
            summary['total'] += 1
        return summary
