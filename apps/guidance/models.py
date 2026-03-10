from django.conf import settings
from django.db import models


class GuidancePhase(models.TextChoices):
    APPLICABILITY = 'applicability', 'Betroffenheit'
    SCOPE = 'scope', 'Scope'
    PROCESSES = 'processes', 'Prozesse'
    ASSESSMENT = 'assessment', 'Bewertung'
    MAPPING = 'mapping', 'Mapping'
    MEASURES = 'measures', 'Maßnahmen'
    EVIDENCE = 'evidence', 'Evidenz'
    REVIEW = 'review', 'Review'


class GuidanceStep(models.Model):
    code = models.CharField(max_length=100, unique=True)
    phase = models.CharField(max_length=50, choices=GuidancePhase.choices)
    title = models.CharField(max_length=255)
    description = models.TextField()
    why_it_matters = models.TextField()
    required_inputs = models.TextField(blank=True)
    expected_outputs = models.TextField(blank=True)
    definition_of_done = models.TextField(blank=True)
    route_name = models.CharField(max_length=100, blank=True)
    cta_label = models.CharField(max_length=100, blank=True)
    sort_order = models.PositiveIntegerField(default=0)
    is_required = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['sort_order', 'title']

    def __str__(self):
        return f'{self.sort_order} - {self.title}'


class TenantJourneyState(models.Model):
    tenant = models.OneToOneField('organizations.Tenant', on_delete=models.CASCADE, related_name='journey_state')
    current_step = models.ForeignKey(GuidanceStep, on_delete=models.SET_NULL, null=True, blank=True, related_name='current_for_tenants')
    last_completed_step = models.ForeignKey(GuidanceStep, on_delete=models.SET_NULL, null=True, blank=True, related_name='last_completed_for_tenants')
    progress_percent = models.PositiveIntegerField(default=0)
    summary = models.TextField(blank=True)
    next_action_text = models.CharField(max_length=255, blank=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'JourneyState<{self.tenant.name}>'
