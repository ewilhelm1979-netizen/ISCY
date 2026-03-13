from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class ApplicabilityAssessment(TenantRelationValidationMixin, TimeStampedModel):
    class Status(models.TextChoices):
        RELEVANT = 'RELEVANT', 'Voraussichtlich relevant'
        POSSIBLY_RELEVANT = 'POSSIBLY_RELEVANT', 'Möglicherweise relevant'
        NOT_DIRECTLY_RELEVANT = 'NOT_DIRECTLY_RELEVANT', 'Derzeit nicht direkt relevant'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='applicability_assessments')
    sector = models.CharField(max_length=255)
    company_size = models.CharField(max_length=255, blank=True)
    critical_services = models.TextField(blank=True)
    supply_chain_role = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices)
    reasoning = models.TextField()

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.tenant} - {self.status}'


class Assessment(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'process': 'tenant_id',
        'owner': 'tenant_id',
    }

    class Status(models.TextChoices):
        FULFILLED = 'FULFILLED', 'Ausreichend erfüllt'
        PARTIAL = 'PARTIAL', 'Teilweise erfüllt'
        INFORMAL = 'INFORMAL', 'Informal vorhanden'
        DOCUMENTED_NOT_IMPLEMENTED = 'DOCUMENTED_NOT_IMPLEMENTED', 'Dokumentiert, aber nicht umgesetzt'
        IMPLEMENTED_NO_EVIDENCE = 'IMPLEMENTED_NO_EVIDENCE', 'Umgesetzt, aber nicht nachweisbar'
        MISSING = 'MISSING', 'Fehlt vollständig'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='assessments')
    process = models.ForeignKey('processes.Process', on_delete=models.CASCADE, related_name='assessments')
    requirement = models.ForeignKey('requirements_app.Requirement', on_delete=models.CASCADE, related_name='assessments')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assessments')
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.MISSING)
    score = models.PositiveSmallIntegerField(default=0)
    notes = models.TextField(blank=True)
    evidence_summary = models.TextField(blank=True)

    class Meta:
        unique_together = ('process', 'requirement')
        ordering = ['requirement__framework', 'requirement__code']

    def __str__(self):
        return f'{self.process} -> {self.requirement}'


class Measure(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'assessment': 'tenant_id',
        'owner': 'tenant_id',
    }

    class Priority(models.TextChoices):
        LOW = 'LOW', 'Low'
        MEDIUM = 'MEDIUM', 'Medium'
        HIGH = 'HIGH', 'High'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        IN_PROGRESS = 'IN_PROGRESS', 'In Progress'
        BLOCKED = 'BLOCKED', 'Blocked'
        DONE = 'DONE', 'Done'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='measures')
    assessment = models.ForeignKey(Assessment, on_delete=models.SET_NULL, null=True, blank=True, related_name='measures')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='measures')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=16, choices=Priority.choices, default=Priority.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    due_date = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['status', 'due_date']

    def __str__(self):
        return self.title


# V20: Import new models so Django can discover them
from .soa_models import SoADocument, SoAEntry  # noqa: E402, F401
from .audit_models import Audit, AuditFinding  # noqa: E402, F401
from .review_models import ManagementReview, ReviewAction  # noqa: E402, F401
