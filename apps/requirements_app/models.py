from django.db import models
from apps.core.models import TimeStampedModel


class MappingVersion(TimeStampedModel):
    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        ACTIVE = 'ACTIVE', 'Aktiv'
        SUPERSEDED = 'SUPERSEDED', 'Ersetzt'

    framework = models.CharField(max_length=32)
    slug = models.SlugField(unique=True)
    title = models.CharField(max_length=255)
    version = models.CharField(max_length=32)
    program_name = models.CharField(max_length=64, default='ISCY')
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    effective_on = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['framework', '-effective_on', '-created_at']

    def __str__(self):
        return f'{self.program_name} {self.framework} {self.version}'


class Requirement(TimeStampedModel):
    class Framework(models.TextChoices):
        ISO27001 = 'ISO27001', 'ISO 27001'
        NIS2 = 'NIS2', 'NIS2'
        KRITIS = 'KRITIS', 'KRITIS'
        CRA = 'CRA', 'Cyber Resilience Act'
        AI_ACT = 'AI_ACT', 'EU AI Act'
        IEC62443 = 'IEC62443', 'IEC 62443'
        ISO_SAE_21434 = 'ISO_SAE_21434', 'ISO/SAE 21434'

    class Coverage(models.TextChoices):
        PRIMARY = 'PRIMARY', 'Primär'
        SUPPORTING = 'SUPPORTING', 'Unterstützend'
        DERIVED = 'DERIVED', 'Abgeleitet'

    framework = models.CharField(max_length=32, choices=Framework.choices)
    code = models.CharField(max_length=64)
    title = models.CharField(max_length=255)
    domain = models.CharField(max_length=255)
    description = models.TextField()
    guidance = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    evidence_required = models.BooleanField(default=True)
    evidence_guidance = models.TextField(blank=True)
    evidence_examples = models.TextField(blank=True)
    sector_package = models.CharField(max_length=64, blank=True, help_text='Optionales Paket wie DIGITAL, FINANCE, CRITICAL_INFRA, ALL')
    legal_reference = models.CharField(max_length=128, blank=True)
    mapped_controls = models.JSONField(default=list, blank=True)
    mapping_rationale = models.TextField(blank=True)
    coverage_level = models.CharField(max_length=16, choices=Coverage.choices, default=Coverage.PRIMARY)
    mapping_version = models.ForeignKey('requirements_app.MappingVersion', on_delete=models.SET_NULL, null=True, blank=True, related_name='requirements')
    primary_source = models.ForeignKey('requirements_app.RegulatorySource', on_delete=models.SET_NULL, null=True, blank=True, related_name='requirements')

    class Meta:
        unique_together = ('framework', 'code')
        ordering = ['framework', 'code']

    def __str__(self):
        return f'{self.framework} - {self.code}'


class RegulatorySource(TimeStampedModel):
    class SourceType(models.TextChoices):
        PRIMARY = 'PRIMARY', 'Primärquelle'
        OFFICIAL_GUIDANCE = 'OFFICIAL_GUIDANCE', 'Offizielle Guidance'
        STANDARD = 'STANDARD', 'Standard'

    framework = models.CharField(max_length=32, choices=Requirement.Framework.choices)
    mapping_version = models.ForeignKey(MappingVersion, on_delete=models.CASCADE, related_name='sources')
    code = models.CharField(max_length=64)
    title = models.CharField(max_length=255)
    authority = models.CharField(max_length=128)
    citation = models.CharField(max_length=255, blank=True)
    url = models.URLField(blank=True)
    source_type = models.CharField(max_length=32, choices=SourceType.choices, default=SourceType.PRIMARY)
    published_on = models.DateField(null=True, blank=True)
    effective_on = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        unique_together = ('mapping_version', 'framework', 'code')
        ordering = ['framework', 'code']

    def __str__(self):
        return f'{self.framework} {self.code}'


class RequirementQuestionMapping(TimeStampedModel):
    class Strength(models.TextChoices):
        PRIMARY = 'PRIMARY', 'Primär'
        SUPPORTING = 'SUPPORTING', 'Unterstützend'

    requirement = models.ForeignKey(Requirement, on_delete=models.CASCADE, related_name='question_mappings')
    mapping_version = models.ForeignKey(MappingVersion, on_delete=models.CASCADE, related_name='question_mappings')
    question = models.ForeignKey('catalog.AssessmentQuestion', on_delete=models.CASCADE, related_name='requirement_mappings')
    strength = models.CharField(max_length=16, choices=Strength.choices, default=Strength.PRIMARY)
    rationale = models.TextField(blank=True)

    class Meta:
        unique_together = ('requirement', 'mapping_version', 'question')
        ordering = ['requirement__framework', 'requirement__code', 'question__sort_order']

    def __str__(self):
        return f'{self.requirement.code} -> {self.question.code}'
