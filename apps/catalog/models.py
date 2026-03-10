from django.db import models
from apps.core.models import TimeStampedModel


class AssessmentDomain(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    weight = models.PositiveIntegerField(default=10)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['sort_order', 'name']

    def __str__(self):
        return self.name


class AssessmentQuestion(TimeStampedModel):
    class Kind(models.TextChoices):
        APPLICABILITY = 'APPLICABILITY', 'Betroffenheit'
        MATURITY = 'MATURITY', 'Reifegrad'

    class Step(models.TextChoices):
        APPLICABILITY = 'applicability', 'Betroffenheit'
        MATURITY = 'maturity', 'Reifegrad'

    domain = models.ForeignKey(AssessmentDomain, on_delete=models.CASCADE, related_name='questions', null=True, blank=True)
    code = models.CharField(max_length=64, unique=True)
    text = models.CharField(max_length=500)
    help_text = models.TextField(blank=True)
    why_it_matters = models.TextField(blank=True)
    question_kind = models.CharField(max_length=20, choices=Kind.choices)
    wizard_step = models.CharField(max_length=20, choices=Step.choices)
    weight = models.PositiveIntegerField(default=10)
    is_required = models.BooleanField(default=True)
    applies_to_iso27001 = models.BooleanField(default=True)
    applies_to_nis2 = models.BooleanField(default=False)
    applies_to_cra = models.BooleanField(default=False)
    applies_to_ai_act = models.BooleanField(default=False)
    applies_to_iec62443 = models.BooleanField(default=False)
    applies_to_iso_sae_21434 = models.BooleanField(default=False)
    applies_to_product_security = models.BooleanField(default=False)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['wizard_step', 'sort_order', 'code']

    def __str__(self):
        return self.text


class AnswerOption(TimeStampedModel):
    question = models.ForeignKey(AssessmentQuestion, on_delete=models.CASCADE, related_name='options')
    slug = models.SlugField(max_length=64)
    label = models.CharField(max_length=255)
    score = models.IntegerField(default=0)
    description = models.TextField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)
    is_na = models.BooleanField(default=False)

    class Meta:
        unique_together = ('question', 'slug')
        ordering = ['question', 'sort_order']

    def __str__(self):
        return f'{self.question.code} - {self.label}'


class RecommendationRule(TimeStampedModel):
    class Priority(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Kritisch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    class Effort(models.TextChoices):
        SMALL = 'SMALL', 'Klein'
        MEDIUM = 'MEDIUM', 'Mittel'
        LARGE = 'LARGE', 'Groß'

    class MeasureType(models.TextChoices):
        ORGANIZATIONAL = 'ORGANIZATIONAL', 'Organisatorisch'
        TECHNICAL = 'TECHNICAL', 'Technisch'
        DOCUMENTARY = 'DOCUMENTARY', 'Dokumentarisch'

    question = models.ForeignKey(AssessmentQuestion, on_delete=models.CASCADE, related_name='recommendation_rules')
    max_score_threshold = models.IntegerField(default=2)
    title = models.CharField(max_length=255)
    description = models.TextField()
    priority = models.CharField(max_length=16, choices=Priority.choices, default=Priority.MEDIUM)
    effort = models.CharField(max_length=16, choices=Effort.choices, default=Effort.MEDIUM)
    measure_type = models.CharField(max_length=20, choices=MeasureType.choices, default=MeasureType.ORGANIZATIONAL)
    owner_role = models.CharField(max_length=64, blank=True)
    target_phase = models.CharField(max_length=64, blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['question', 'sort_order']

    def __str__(self):
        return self.title
