from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class ReportSnapshot(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'session': 'tenant_id',
    }

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='report_snapshots')
    session = models.ForeignKey('wizard.AssessmentSession', on_delete=models.CASCADE, related_name='report_snapshots')
    title = models.CharField(max_length=255)
    executive_summary = models.TextField(blank=True)
    applicability_result = models.CharField(max_length=255, blank=True)
    iso_readiness_percent = models.PositiveIntegerField(default=0)
    nis2_readiness_percent = models.PositiveIntegerField(default=0)
    cra_readiness_percent = models.PositiveIntegerField(default=0)
    ai_act_readiness_percent = models.PositiveIntegerField(default=0)
    iec62443_readiness_percent = models.PositiveIntegerField(default=0)
    iso_sae_21434_readiness_percent = models.PositiveIntegerField(default=0)
    regulatory_matrix_json = models.JSONField(default=dict, blank=True)
    product_security_json = models.JSONField(default=dict, blank=True)
    top_gaps_json = models.JSONField(default=list, blank=True)
    top_measures_json = models.JSONField(default=list, blank=True)
    roadmap_summary = models.JSONField(default=list, blank=True)
    domain_scores_json = models.JSONField(default=list, blank=True)
    next_steps_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
