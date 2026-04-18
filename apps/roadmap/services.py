import json
from dataclasses import dataclass, field
from datetime import date, datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from django.conf import settings

from apps.roadmap.models import RoadmapTask, RoadmapTaskDependency


class RoadmapRelatedList:
    def __init__(self, items=None, known_count: int | None = None):
        self._items = list(items or [])
        self._known_count = known_count

    def all(self):
        return list(self._items)

    def count(self):
        if self._known_count is not None:
            return self._known_count
        return len(self._items)

    def prefetch_related(self, *_args):
        return self

    def select_related(self, *_args):
        return self

    def add(self, item):
        self._items.append(item)
        self._known_count = None

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return self.count()

    def __getitem__(self, index):
        return self._items[index]


@dataclass
class RoadmapPlanBridgeItem:
    id: int
    tenant: object
    tenant_id: int
    tenant_name: str
    session_id: int
    title: str
    summary: str
    overall_priority: str
    planned_start: date | None
    phase_count: int
    task_count: int
    open_task_count: int
    created_at: datetime | None
    updated_at: datetime | None
    phases: RoadmapRelatedList = field(default_factory=RoadmapRelatedList)

    @property
    def pk(self) -> int:
        return self.id


@dataclass
class RoadmapPhaseBridgeItem:
    id: int
    plan: RoadmapPlanBridgeItem
    plan_id: int
    name: str
    sort_order: int
    objective: str
    duration_weeks: int
    planned_start: date | None
    planned_end: date | None
    task_count: int
    created_at: datetime | None
    updated_at: datetime | None
    tasks: RoadmapRelatedList = field(default_factory=RoadmapRelatedList)

    @property
    def pk(self) -> int:
        return self.id


@dataclass
class RoadmapTaskBridgeItem:
    id: int
    phase: RoadmapPhaseBridgeItem
    phase_id: int
    phase_name: str
    measure_id: int | None
    title: str
    description: str
    priority: str
    owner_role: str
    due_in_days: int
    dependency_text: str
    status: str
    status_label: str
    planned_start: date | None
    due_date: date | None
    notes: str
    incoming_dependency_count: int
    created_at: datetime | None
    updated_at: datetime | None
    incoming_dependencies: RoadmapRelatedList = field(default_factory=RoadmapRelatedList)

    @property
    def pk(self) -> int:
        return self.id

    def get_status_display(self) -> str:
        return self.status_label


@dataclass
class RoadmapTaskDependencyBridgeItem:
    id: int
    predecessor: RoadmapTaskBridgeItem | None
    predecessor_id: int
    predecessor_title: str
    successor: RoadmapTaskBridgeItem | None
    successor_id: int
    successor_title: str
    dependency_type: str
    dependency_type_label: str
    rationale: str
    created_at: datetime | None
    updated_at: datetime | None

    @property
    def pk(self) -> int:
        return self.id

    def get_dependency_type_display(self) -> str:
        return self.dependency_type_label


@dataclass
class RoadmapPlanBridgeDetail:
    plan: RoadmapPlanBridgeItem
    tasks: list[RoadmapTaskBridgeItem]
    dependencies: list[RoadmapTaskDependencyBridgeItem]


class RoadmapRustClient:
    @staticmethod
    def _base_url() -> str:
        base = (getattr(settings, 'RUST_BACKEND_URL', '') or '').strip()
        return base.rstrip('/')

    @staticmethod
    def fetch_plans(request, tenant, timeout: int = 8) -> list[RoadmapPlanBridgeItem]:
        base = RoadmapRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RoadmapRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/roadmap/plans',
        )
        with urlopen(rust_request, timeout=timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))

        tenant_id = RoadmapRustClient._int_field(payload, 'tenant_id')
        if tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Roadmapliste gehoert nicht zum angefragten Tenant.')

        return [
            RoadmapRustClient._plan_from_payload(item, tenant)
            for item in payload.get('plans', [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def fetch_plan_detail(request, tenant, plan_id: int, timeout: int = 8) -> RoadmapPlanBridgeDetail | None:
        base = RoadmapRustClient._base_url()
        if not base:
            raise RuntimeError('RUST_BACKEND_URL ist nicht gesetzt.')

        rust_request = RoadmapRustClient._authenticated_request(
            request,
            tenant,
            f'{base}/api/v1/roadmap/plans/{int(plan_id)}',
        )
        try:
            with urlopen(rust_request, timeout=timeout) as response:
                payload = json.loads(response.read().decode('utf-8'))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise

        plan_payload = payload.get('plan') or {}
        if not isinstance(plan_payload, dict):
            raise RuntimeError('Rust-Roadmapdetail hat kein plan-Objekt geliefert.')
        plan = RoadmapRustClient._plan_from_payload(plan_payload, tenant)
        if plan.tenant_id != int(tenant.id):
            raise RuntimeError('Rust-Roadmapdetail gehoert nicht zum angefragten Tenant.')

        phase_by_id: dict[int, RoadmapPhaseBridgeItem] = {}
        for item in payload.get('phases', []):
            if not isinstance(item, dict):
                continue
            phase = RoadmapRustClient._phase_from_payload(item, plan)
            phase_by_id[phase.id] = phase
            plan.phases.add(phase)

        tasks: list[RoadmapTaskBridgeItem] = []
        task_by_id: dict[int, RoadmapTaskBridgeItem] = {}
        for item in payload.get('tasks', []):
            if not isinstance(item, dict):
                continue
            phase_id = RoadmapRustClient._int_field(item, 'phase_id')
            phase = phase_by_id.get(phase_id)
            if phase is None:
                continue
            task = RoadmapRustClient._task_from_payload(item, phase)
            tasks.append(task)
            task_by_id[task.id] = task
            phase.tasks.add(task)

        dependencies: list[RoadmapTaskDependencyBridgeItem] = []
        for item in payload.get('dependencies', []):
            if not isinstance(item, dict):
                continue
            dependency = RoadmapRustClient._dependency_from_payload(item, task_by_id)
            dependencies.append(dependency)
            if dependency.successor is not None:
                dependency.successor.incoming_dependencies.add(dependency)

        return RoadmapPlanBridgeDetail(plan=plan, tasks=tasks, dependencies=dependencies)

    @staticmethod
    def _plan_from_payload(item: dict, tenant) -> RoadmapPlanBridgeItem:
        phase_count = RoadmapRustClient._int_field(item, 'phase_count')
        return RoadmapPlanBridgeItem(
            id=RoadmapRustClient._int_field(item, 'id'),
            tenant=tenant,
            tenant_id=RoadmapRustClient._int_field(item, 'tenant_id'),
            tenant_name=str(item.get('tenant_name') or getattr(tenant, 'name', '')),
            session_id=RoadmapRustClient._int_field(item, 'session_id'),
            title=str(item.get('title') or ''),
            summary=str(item.get('summary') or ''),
            overall_priority=str(item.get('overall_priority') or ''),
            planned_start=RoadmapRustClient._date_field(item, 'planned_start'),
            phase_count=phase_count,
            task_count=RoadmapRustClient._int_field(item, 'task_count'),
            open_task_count=RoadmapRustClient._int_field(item, 'open_task_count'),
            created_at=RoadmapRustClient._datetime_field(item, 'created_at'),
            updated_at=RoadmapRustClient._datetime_field(item, 'updated_at'),
            phases=RoadmapRelatedList(known_count=phase_count),
        )

    @staticmethod
    def _phase_from_payload(item: dict, plan: RoadmapPlanBridgeItem) -> RoadmapPhaseBridgeItem:
        task_count = RoadmapRustClient._int_field(item, 'task_count')
        return RoadmapPhaseBridgeItem(
            id=RoadmapRustClient._int_field(item, 'id'),
            plan=plan,
            plan_id=RoadmapRustClient._int_field(item, 'plan_id'),
            name=str(item.get('name') or ''),
            sort_order=RoadmapRustClient._int_field(item, 'sort_order'),
            objective=str(item.get('objective') or ''),
            duration_weeks=RoadmapRustClient._int_field(item, 'duration_weeks'),
            planned_start=RoadmapRustClient._date_field(item, 'planned_start'),
            planned_end=RoadmapRustClient._date_field(item, 'planned_end'),
            task_count=task_count,
            created_at=RoadmapRustClient._datetime_field(item, 'created_at'),
            updated_at=RoadmapRustClient._datetime_field(item, 'updated_at'),
            tasks=RoadmapRelatedList(known_count=task_count),
        )

    @staticmethod
    def _task_from_payload(item: dict, phase: RoadmapPhaseBridgeItem) -> RoadmapTaskBridgeItem:
        status = str(item.get('status') or RoadmapTask.Status.OPEN)
        return RoadmapTaskBridgeItem(
            id=RoadmapRustClient._int_field(item, 'id'),
            phase=phase,
            phase_id=RoadmapRustClient._int_field(item, 'phase_id'),
            phase_name=str(item.get('phase_name') or phase.name),
            measure_id=RoadmapRustClient._optional_int_field(item, 'measure_id'),
            title=str(item.get('title') or ''),
            description=str(item.get('description') or ''),
            priority=str(item.get('priority') or ''),
            owner_role=str(item.get('owner_role') or ''),
            due_in_days=RoadmapRustClient._int_field(item, 'due_in_days'),
            dependency_text=str(item.get('dependency_text') or ''),
            status=status,
            status_label=str(item.get('status_label') or dict(RoadmapTask.Status.choices).get(status, status)),
            planned_start=RoadmapRustClient._date_field(item, 'planned_start'),
            due_date=RoadmapRustClient._date_field(item, 'due_date'),
            notes=str(item.get('notes') or ''),
            incoming_dependency_count=RoadmapRustClient._int_field(item, 'incoming_dependency_count'),
            created_at=RoadmapRustClient._datetime_field(item, 'created_at'),
            updated_at=RoadmapRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _dependency_from_payload(
        item: dict,
        task_by_id: dict[int, RoadmapTaskBridgeItem],
    ) -> RoadmapTaskDependencyBridgeItem:
        predecessor_id = RoadmapRustClient._int_field(item, 'predecessor_id')
        successor_id = RoadmapRustClient._int_field(item, 'successor_id')
        dependency_type = str(item.get('dependency_type') or RoadmapTaskDependency.DependencyType.FINISH_TO_START)
        return RoadmapTaskDependencyBridgeItem(
            id=RoadmapRustClient._int_field(item, 'id'),
            predecessor=task_by_id.get(predecessor_id),
            predecessor_id=predecessor_id,
            predecessor_title=str(item.get('predecessor_title') or ''),
            successor=task_by_id.get(successor_id),
            successor_id=successor_id,
            successor_title=str(item.get('successor_title') or ''),
            dependency_type=dependency_type,
            dependency_type_label=str(
                item.get('dependency_type_label')
                or dict(RoadmapTaskDependency.DependencyType.choices).get(dependency_type, dependency_type)
            ),
            rationale=str(item.get('rationale') or ''),
            created_at=RoadmapRustClient._datetime_field(item, 'created_at'),
            updated_at=RoadmapRustClient._datetime_field(item, 'updated_at'),
        )

    @staticmethod
    def _authenticated_request(request, tenant, url: str) -> Request:
        user = getattr(request, 'user', None)
        user_id = getattr(user, 'id', None)
        if not user_id:
            raise RuntimeError('Roadmap-Rust-Bridge braucht einen authentifizierten User.')

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

    @staticmethod
    def _datetime_field(payload: dict, key: str) -> datetime | None:
        value = str(payload.get(key) or '').strip()
        if not value:
            return None
        normalized = value.replace('Z', '+00:00')
        return datetime.fromisoformat(normalized)


class RoadmapRegisterBridge:
    @staticmethod
    def fetch_list(request, tenant):
        if tenant is None:
            return None

        backend = str(getattr(settings, 'ROADMAP_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not RoadmapRustClient._base_url():
            if RoadmapRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust roadmap register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return RoadmapRustClient.fetch_plans(request, tenant)
        except Exception as exc:
            if RoadmapRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust roadmap register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def fetch_detail(request, tenant, plan_id):
        if tenant is None or not plan_id:
            return None

        backend = str(getattr(settings, 'ROADMAP_REGISTER_BACKEND', 'rust_service') or '').strip().lower()
        if backend != 'rust_service':
            return None

        if not RoadmapRustClient._base_url():
            if RoadmapRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust roadmap register backend ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.')
            return None

        try:
            return RoadmapRustClient.fetch_plan_detail(request, tenant, int(plan_id))
        except Exception as exc:
            if RoadmapRegisterBridge._strict_rust_mode():
                raise RuntimeError('Rust roadmap register backend ist aktiv, aber nicht erreichbar.') from exc
            return None

    @staticmethod
    def _strict_rust_mode() -> bool:
        return bool(getattr(settings, 'RUST_STRICT_MODE', False))
