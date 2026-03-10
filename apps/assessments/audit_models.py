"""V20: Audit-Modul – internes/externes Audit, Findings, Corrective Actions."""
from django.db import models
from apps.core.models import TimeStampedModel


class Audit(TimeStampedModel):
    class AuditType(models.TextChoices):
        INTERNAL = 'INTERNAL', 'Internes Audit'
        EXTERNAL = 'EXTERNAL', 'Externes Audit'
        SURVEILLANCE = 'SURVEILLANCE', 'Ueberwachungsaudit'
        RECERTIFICATION = 'RECERTIFICATION', 'Rezertifizierungsaudit'

    class Status(models.TextChoices):
        PLANNED = 'PLANNED', 'Geplant'
        IN_PROGRESS = 'IN_PROGRESS', 'Laufend'
        COMPLETED = 'COMPLETED', 'Abgeschlossen'
        CANCELLED = 'CANCELLED', 'Abgebrochen'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='audits')
    title = models.CharField(max_length=255)
    audit_type = models.CharField(max_length=20, choices=AuditType.choices, default=AuditType.INTERNAL)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PLANNED)
    lead_auditor = models.CharField(max_length=255, blank=True)
    audit_team = models.TextField(blank=True, help_text='Auditteam-Mitglieder, je Zeile ein Name')
    scope = models.TextField(blank=True, help_text='Auditumfang und -kriterien')
    objectives = models.TextField(blank=True)
    planned_start = models.DateField(null=True, blank=True)
    planned_end = models.DateField(null=True, blank=True)
    actual_start = models.DateField(null=True, blank=True)
    actual_end = models.DateField(null=True, blank=True)
    conclusion = models.TextField(blank=True, help_text='Gesamtfazit des Audits')
    created_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='created_audits')

    class Meta:
        ordering = ['-planned_start', '-created_at']

    def __str__(self):
        return self.title

    @property
    def findings_count(self):
        return self.findings.count()

    @property
    def open_findings_count(self):
        return self.findings.exclude(status__in=['CLOSED', 'VERIFIED']).count()


class AuditFinding(TimeStampedModel):
    class Severity(models.TextChoices):
        MAJOR_NC = 'MAJOR_NC', 'Hauptabweichung (Major NC)'
        MINOR_NC = 'MINOR_NC', 'Nebenabweichung (Minor NC)'
        OBSERVATION = 'OBSERVATION', 'Beobachtung'
        OPPORTUNITY = 'OPPORTUNITY', 'Verbesserungspotenzial'
        POSITIVE = 'POSITIVE', 'Positive Feststellung'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        IN_PROGRESS = 'IN_PROGRESS', 'In Bearbeitung'
        CORRECTIVE_ACTION = 'CORRECTIVE_ACTION', 'Korrekturmassnahme definiert'
        IMPLEMENTED = 'IMPLEMENTED', 'Umgesetzt'
        VERIFIED = 'VERIFIED', 'Verifiziert / wirksam'
        CLOSED = 'CLOSED', 'Geschlossen'

    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name='findings')
    finding_number = models.CharField(max_length=32)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MINOR_NC)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    requirement_reference = models.CharField(max_length=128, blank=True, help_text='z.B. A.5.1, NIS2-21-2a')
    evidence_reference = models.TextField(blank=True)
    responsible = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_findings')
    due_date = models.DateField(null=True, blank=True)
    root_cause = models.TextField(blank=True)
    corrective_action = models.TextField(blank=True)
    verification_notes = models.TextField(blank=True)
    verified_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_findings')
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['severity', 'finding_number']

    def __str__(self):
        return f'{self.finding_number}: {self.title}'
