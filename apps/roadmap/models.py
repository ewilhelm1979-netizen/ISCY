from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class RoadmapPlan(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'session': 'tenant_id',
    }

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='roadmap_plans')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.CASCADE, related_name='roadmap_plans')
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    overall_priority = models.CharField(max_length=32, blank=True)
    planned_start = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class RoadmapPhase(TenantRelationValidationMixin, TimeStampedModel):
    tenant_source = 'plan__tenant_id'

    plan = models.ForeignKey(RoadmapPlan, on_delete=models.CASCADE, related_name='phases')
    name = models.CharField(max_length=255)
    sort_order = models.PositiveIntegerField(default=0)
    objective = models.TextField(blank=True)
    duration_weeks = models.PositiveIntegerField(default=2)
    planned_start = models.DateField(null=True, blank=True)
    planned_end = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['sort_order']

    def __str__(self):
        return self.name


class RoadmapTask(TenantRelationValidationMixin, TimeStampedModel):
    tenant_source = 'phase__plan__tenant_id'
    tenant_relation_fields = {
        'measure': 'session__tenant_id',
    }

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        PLANNED = 'PLANNED', 'Geplant'
        IN_PROGRESS = 'IN_PROGRESS', 'In Umsetzung'
        BLOCKED = 'BLOCKED', 'Blockiert'
        DONE = 'DONE', 'Erledigt'

    phase = models.ForeignKey(RoadmapPhase, on_delete=models.CASCADE, related_name='tasks')
    measure = models.ForeignKey('wizard.GeneratedMeasure', on_delete=models.SET_NULL, null=True, blank=True, related_name='roadmap_tasks')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=32, blank=True)
    owner_role = models.CharField(max_length=64, blank=True)
    due_in_days = models.PositiveIntegerField(default=30)
    dependency_text = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    planned_start = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['priority', 'title']

    def __str__(self):
        return self.title

    @property
    def dependencies(self):
        return self.incoming_dependencies.select_related('predecessor').all()


class RoadmapTaskDependency(TenantRelationValidationMixin, TimeStampedModel):
    tenant_source = 'predecessor__phase__plan__tenant_id'
    tenant_relation_fields = {
        'predecessor': 'phase__plan__tenant_id',
        'successor': 'phase__plan__tenant_id',
    }

    class DependencyType(models.TextChoices):
        FINISH_TO_START = 'FS', 'Finish-to-Start'
        START_TO_START = 'SS', 'Start-to-Start'

    predecessor = models.ForeignKey(RoadmapTask, on_delete=models.CASCADE, related_name='outgoing_dependencies')
    successor = models.ForeignKey(RoadmapTask, on_delete=models.CASCADE, related_name='incoming_dependencies')
    dependency_type = models.CharField(max_length=2, choices=DependencyType.choices, default=DependencyType.FINISH_TO_START)
    rationale = models.CharField(max_length=255, blank=True)

    class Meta:
        unique_together = ('predecessor', 'successor')
        ordering = ['predecessor_id', 'successor_id']

    def __str__(self):
        return f'{self.predecessor} -> {self.successor}'
