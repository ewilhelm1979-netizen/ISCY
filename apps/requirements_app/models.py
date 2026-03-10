from django.db import models
from apps.core.models import TimeStampedModel


class Requirement(TimeStampedModel):
    class Framework(models.TextChoices):
        ISO27001 = 'ISO27001', 'ISO 27001'
        NIS2 = 'NIS2', 'NIS2'
        CRA = 'CRA', 'Cyber Resilience Act'
        AI_ACT = 'AI_ACT', 'EU AI Act'
        IEC62443 = 'IEC62443', 'IEC 62443'
        ISO_SAE_21434 = 'ISO_SAE_21434', 'ISO/SAE 21434'

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

    class Meta:
        unique_together = ('framework', 'code')
        ordering = ['framework', 'code']

    def __str__(self):
        return f'{self.framework} - {self.code}'
