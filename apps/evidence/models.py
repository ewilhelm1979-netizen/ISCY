from django.db import models
from apps.core.models import TimeStampedModel
from apps.evidence.validators import validate_evidence_file


class EvidenceItem(TimeStampedModel):
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        SUBMITTED = 'SUBMITTED', 'Zur Prüfung eingereicht'
        APPROVED = 'APPROVED', 'Freigegeben'
        REJECTED = 'REJECTED', 'Abgelehnt'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='evidence_items')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.CASCADE, related_name='evidence_items', null=True, blank=True)
    domain = models.ForeignKey('catalog.AssessmentDomain', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_items')
    measure = models.ForeignKey('wizard.GeneratedMeasure', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_items')
    requirement = models.ForeignKey('requirements_app.Requirement', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_items')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    linked_requirement = models.CharField(max_length=128, blank=True)
    file = models.FileField(upload_to='evidence/%Y/%m/', blank=True, null=True, validators=[validate_evidence_file])
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_evidence')
    review_notes = models.TextField(blank=True)
    reviewed_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_evidence')
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-updated_at', 'title']

    def __str__(self):
        return self.title

    @property
    def requirement_display(self):
        if self.requirement:
            return f'{self.requirement.framework} {self.requirement.code} – {self.requirement.title}'
        return self.linked_requirement


class RequirementEvidenceNeed(TimeStampedModel):
    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        PARTIAL = 'PARTIAL', 'Teilweise abgedeckt'
        COVERED = 'COVERED', 'Abgedeckt'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='evidence_needs')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.CASCADE, related_name='evidence_needs', null=True, blank=True)
    requirement = models.ForeignKey('requirements_app.Requirement', on_delete=models.CASCADE, related_name='evidence_needs')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_mandatory = models.BooleanField(default=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    rationale = models.TextField(blank=True)
    covered_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ('tenant', 'session', 'requirement')
        ordering = ['status', 'requirement__framework', 'requirement__code']

    def __str__(self):
        return self.title
