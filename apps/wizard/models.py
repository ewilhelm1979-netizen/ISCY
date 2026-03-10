from django.conf import settings
from django.db import models
from apps.core.models import TimeStampedModel


class AssessmentSession(TimeStampedModel):
    class Type(models.TextChoices):
        APPLICABILITY = 'APPLICABILITY', 'NIS2-/KRITIS-Relevanz prüfen'
        ISO_READINESS = 'ISO_READINESS', 'ISO-27001-Readiness bewerten'
        FULL = 'FULL', 'Vollständige ISMS-/NIS2-Gap-Analyse'

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        IN_PROGRESS = 'IN_PROGRESS', 'In Bearbeitung'
        COMPLETED = 'COMPLETED', 'Abgeschlossen'

    class Step(models.TextChoices):
        PROFILE = 'profile', 'Unternehmensprofil'
        APPLICABILITY = 'applicability', 'Betroffenheit'
        SCOPE = 'scope', 'Scope & Struktur'
        MATURITY = 'maturity', 'Reifegradanalyse'
        RESULTS = 'results', 'Ergebnis'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='assessment_sessions')
    assessment_type = models.CharField(max_length=24, choices=Type.choices, default=Type.FULL)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    current_step = models.CharField(max_length=24, choices=Step.choices, default=Step.PROFILE)
    started_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='started_sessions')
    applicability_result = models.CharField(max_length=64, blank=True)
    applicability_reasoning = models.TextField(blank=True)
    executive_summary = models.TextField(blank=True)
    progress_percent = models.PositiveIntegerField(default=0)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f'{self.tenant} - {self.get_assessment_type_display()}'


class SessionAnswer(TimeStampedModel):
    session = models.ForeignKey(AssessmentSession, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey('catalog.AssessmentQuestion', on_delete=models.CASCADE, related_name='session_answers')
    selected_option = models.ForeignKey('catalog.AnswerOption', on_delete=models.SET_NULL, null=True, blank=True, related_name='session_answers')
    free_text = models.TextField(blank=True)
    score = models.IntegerField(default=0)
    # F08: N/A-Flag, damit N/A-Antworten aus Score- und Gap-Berechnung ausgeschlossen werden
    is_na = models.BooleanField(default=False)
    comment = models.TextField(blank=True)

    class Meta:
        unique_together = ('session', 'question')
        ordering = ['question__sort_order']

    def __str__(self):
        return f'{self.session_id} - {self.question.code}'


class DomainScore(TimeStampedModel):
    session = models.ForeignKey(AssessmentSession, on_delete=models.CASCADE, related_name='domain_scores')
    domain = models.ForeignKey('catalog.AssessmentDomain', on_delete=models.CASCADE, related_name='domain_scores')
    score_raw = models.IntegerField(default=0)
    score_percent = models.PositiveIntegerField(default=0)
    maturity_level = models.CharField(max_length=64, blank=True)
    gap_level = models.CharField(max_length=32, blank=True)

    class Meta:
        unique_together = ('session', 'domain')
        ordering = ['domain__sort_order']

    def __str__(self):
        return f'{self.session_id} - {self.domain.code}'


class GeneratedGap(TimeStampedModel):
    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Kritisch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    session = models.ForeignKey(AssessmentSession, on_delete=models.CASCADE, related_name='generated_gaps')
    domain = models.ForeignKey('catalog.AssessmentDomain', on_delete=models.CASCADE, related_name='generated_gaps')
    question = models.ForeignKey('catalog.AssessmentQuestion', on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['severity', 'domain__sort_order', 'title']

    def __str__(self):
        return self.title


class GeneratedMeasure(TimeStampedModel):
    class Priority(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Kritisch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    class Effort(models.TextChoices):
        SMALL = 'SMALL', 'Klein'
        MEDIUM = 'MEDIUM', 'Mittel'
        LARGE = 'LARGE', 'Groß'

    class Type(models.TextChoices):
        ORGANIZATIONAL = 'ORGANIZATIONAL', 'Organisatorisch'
        TECHNICAL = 'TECHNICAL', 'Technisch'
        DOCUMENTARY = 'DOCUMENTARY', 'Dokumentarisch'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        PLANNED = 'PLANNED', 'Geplant'
        IN_PROGRESS = 'IN_PROGRESS', 'In Umsetzung'
        DONE = 'DONE', 'Erledigt'

    session = models.ForeignKey(AssessmentSession, on_delete=models.CASCADE, related_name='generated_measures')
    domain = models.ForeignKey('catalog.AssessmentDomain', on_delete=models.SET_NULL, null=True, blank=True, related_name='generated_measures')
    question = models.ForeignKey('catalog.AssessmentQuestion', on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=16, choices=Priority.choices, default=Priority.MEDIUM)
    effort = models.CharField(max_length=16, choices=Effort.choices, default=Effort.MEDIUM)
    measure_type = models.CharField(max_length=20, choices=Type.choices, default=Type.ORGANIZATIONAL)
    target_phase = models.CharField(max_length=64, blank=True)
    owner_role = models.CharField(max_length=64, blank=True)
    reason = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)

    class Meta:
        ordering = ['priority', 'domain__sort_order', 'title']

    def __str__(self):
        return self.title
