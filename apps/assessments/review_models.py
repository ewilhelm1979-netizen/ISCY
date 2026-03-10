"""V20: Management-Review-Workflow mit Agenda und Protokoll."""
from django.db import models
from apps.core.models import TimeStampedModel


class ManagementReview(TimeStampedModel):
    class Status(models.TextChoices):
        PLANNED = 'PLANNED', 'Geplant'
        AGENDA_SET = 'AGENDA_SET', 'Agenda erstellt'
        IN_SESSION = 'IN_SESSION', 'Sitzung laeuft'
        PROTOCOL_DRAFT = 'PROTOCOL_DRAFT', 'Protokoll-Entwurf'
        COMPLETED = 'COMPLETED', 'Abgeschlossen'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='management_reviews')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.SET_NULL, null=True, blank=True, related_name='management_reviews')
    title = models.CharField(max_length=255, default='Management Review')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNED)
    review_date = models.DateField(null=True, blank=True)
    chairperson = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='chaired_reviews')
    attendees = models.TextField(blank=True, help_text='Teilnehmer, je Zeile ein Name/Rolle')
    location = models.CharField(max_length=255, blank=True)

    # ISO 27001 Kap. 9.3 – Inputs
    input_isms_status = models.TextField(blank=True, help_text='Status des ISMS seit letzter Review')
    input_audit_results = models.TextField(blank=True, help_text='Ergebnisse interner/externer Audits')
    input_risk_status = models.TextField(blank=True, help_text='Aktueller Risikostatus und Veraenderungen')
    input_incidents = models.TextField(blank=True, help_text='Sicherheitsvorfaelle und Trends')
    input_metrics = models.TextField(blank=True, help_text='Kennzahlen und Messergebnisse')
    input_feedback = models.TextField(blank=True, help_text='Feedback von interessierten Parteien')
    input_improvement = models.TextField(blank=True, help_text='Moeglichkeiten zur Verbesserung')
    input_changes = models.TextField(blank=True, help_text='Aenderungen die das ISMS betreffen')

    # Outputs / Entscheidungen
    output_decisions = models.TextField(blank=True, help_text='Getroffene Entscheidungen')
    output_actions = models.TextField(blank=True, help_text='Beschlossene Massnahmen mit Verantwortlichen und Fristen')
    output_resource_needs = models.TextField(blank=True, help_text='Ressourcenbedarf')
    output_improvement = models.TextField(blank=True, help_text='Verbesserungsmassnahmen')

    # Protocol
    protocol_summary = models.TextField(blank=True, help_text='Zusammenfassung des Protokolls')
    next_review_date = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['-review_date', '-created_at']

    def __str__(self):
        return f'{self.title} – {self.review_date or "ungeplant"}'


class ReviewAction(TimeStampedModel):
    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        IN_PROGRESS = 'IN_PROGRESS', 'In Bearbeitung'
        DONE = 'DONE', 'Erledigt'
        OVERDUE = 'OVERDUE', 'Ueberfaellig'

    review = models.ForeignKey(ManagementReview, on_delete=models.CASCADE, related_name='actions')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    responsible = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='review_actions')
    due_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    completion_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['status', 'due_date']

    def __str__(self):
        return self.title
