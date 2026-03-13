"""V20: Statement of Applicability (SoA) – ISO 27001 Pflichtdokument."""
from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class SoADocument(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'session': 'tenant_id',
        'approved_by': 'tenant_id',
    }

    """Ein SoA-Dokument pro Tenant/Session."""
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        IN_REVIEW = 'IN_REVIEW', 'In Pruefung'
        APPROVED = 'APPROVED', 'Freigegeben'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='soa_documents')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.SET_NULL, null=True, blank=True, related_name='soa_documents')
    title = models.CharField(max_length=255, default='Statement of Applicability')
    version = models.CharField(max_length=32, default='1.0')
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    approved_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_soas')
    approved_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.title} v{self.version} ({self.tenant.name})'

    @property
    def applicable_count(self):
        return self.entries.filter(is_applicable=True).count()

    @property
    def not_applicable_count(self):
        return self.entries.filter(is_applicable=False).count()

    @property
    def implemented_count(self):
        return self.entries.filter(is_applicable=True, implementation_status='IMPLEMENTED').count()


class SoAEntry(TenantRelationValidationMixin, TimeStampedModel):
    tenant_source = 'soa__tenant_id'
    tenant_relation_fields = {
        'soa': 'tenant_id',
        'control_owner': 'tenant_id',
    }

    """Eine Zeile im SoA – entspricht einem Annex-A Control."""
    class ImplementationStatus(models.TextChoices):
        NOT_STARTED = 'NOT_STARTED', 'Nicht begonnen'
        PARTIAL = 'PARTIAL', 'Teilweise umgesetzt'
        IMPLEMENTED = 'IMPLEMENTED', 'Umgesetzt'
        NOT_APPLICABLE = 'NOT_APPLICABLE', 'Nicht anwendbar'

    soa = models.ForeignKey(SoADocument, on_delete=models.CASCADE, related_name='entries')
    requirement = models.ForeignKey('requirements_app.Requirement', on_delete=models.CASCADE, related_name='soa_entries')
    is_applicable = models.BooleanField(default=True)
    justification = models.TextField(blank=True, help_text='Begruendung fuer Anwendbarkeit oder Ausschluss')
    implementation_status = models.CharField(max_length=20, choices=ImplementationStatus.choices, default=ImplementationStatus.NOT_STARTED)
    control_owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='soa_controls')
    evidence_reference = models.TextField(blank=True, help_text='Verweis auf Evidenzen oder Dokumente')
    notes = models.TextField(blank=True)

    class Meta:
        unique_together = ('soa', 'requirement')
        ordering = ['requirement__framework', 'requirement__code']

    def __str__(self):
        return f'{self.requirement.code} – {"Anwendbar" if self.is_applicable else "Ausgeschlossen"}'
