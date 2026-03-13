"""V20: Erweitertes Risikoregister mit 5x5 Matrix."""
from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class RiskCategory(TenantRelationValidationMixin, TimeStampedModel):
    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='risk_categories')
    name = models.CharField(max_length=128)
    description = models.TextField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['sort_order', 'name']
        verbose_name_plural = 'Risk categories'

    def __str__(self):
        return self.name


class Risk(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'category': 'tenant_id',
        'process': 'tenant_id',
        'asset': 'tenant_id',
        'owner': 'tenant_id',
        'accepted_by': 'tenant_id',
    }

    IMPACT_CHOICES = [(1, '1 – Unerheblich'), (2, '2 – Gering'), (3, '3 – Mittel'), (4, '4 – Hoch'), (5, '5 – Kritisch')]
    LIKELIHOOD_CHOICES = [(1, '1 – Unwahrscheinlich'), (2, '2 – Selten'), (3, '3 – Moeglich'), (4, '4 – Wahrscheinlich'), (5, '5 – Sehr wahrscheinlich')]

    class Status(models.TextChoices):
        IDENTIFIED = 'IDENTIFIED', 'Identifiziert'
        ANALYZING = 'ANALYZING', 'In Analyse'
        TREATING = 'TREATING', 'In Behandlung'
        ACCEPTED = 'ACCEPTED', 'Akzeptiert'
        MITIGATED = 'MITIGATED', 'Gemindert'
        TRANSFERRED = 'TRANSFERRED', 'Transferiert'
        AVOIDED = 'AVOIDED', 'Vermieden'
        CLOSED = 'CLOSED', 'Geschlossen'

    class Treatment(models.TextChoices):
        MITIGATE = 'MITIGATE', 'Mindern'
        ACCEPT = 'ACCEPT', 'Akzeptieren'
        TRANSFER = 'TRANSFER', 'Transferieren'
        AVOID = 'AVOID', 'Vermeiden'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='risks')
    category = models.ForeignKey(RiskCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='risks')
    process = models.ForeignKey('processes.Process', on_delete=models.SET_NULL, null=True, blank=True, related_name='risks')
    asset = models.ForeignKey('assets_app.InformationAsset', on_delete=models.SET_NULL, null=True, blank=True, related_name='risks')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_risks')
    title = models.CharField(max_length=255)
    description = models.TextField()
    threat = models.TextField(blank=True, help_text='Bedrohungsbeschreibung')
    vulnerability = models.TextField(blank=True, help_text='Schwachstelle die ausgenutzt werden kann')

    # 5x5 Matrix: Impact x Likelihood
    impact = models.IntegerField(choices=IMPACT_CHOICES, default=3)
    likelihood = models.IntegerField(choices=LIKELIHOOD_CHOICES, default=3)

    # Residual risk after treatment
    residual_impact = models.IntegerField(choices=IMPACT_CHOICES, null=True, blank=True)
    residual_likelihood = models.IntegerField(choices=LIKELIHOOD_CHOICES, null=True, blank=True)

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.IDENTIFIED)
    treatment_strategy = models.CharField(max_length=16, choices=Treatment.choices, blank=True)
    treatment_plan = models.TextField(blank=True)
    treatment_due_date = models.DateField(null=True, blank=True)
    accepted_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='accepted_risks')
    accepted_at = models.DateTimeField(null=True, blank=True)
    review_date = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['-impact', '-likelihood', 'title']

    @property
    def score(self):
        return self.impact * self.likelihood

    @property
    def residual_score(self):
        if self.residual_impact and self.residual_likelihood:
            return self.residual_impact * self.residual_likelihood
        return None

    @property
    def risk_level(self):
        s = self.score
        if s >= 20: return 'CRITICAL'
        if s >= 12: return 'HIGH'
        if s >= 6: return 'MEDIUM'
        return 'LOW'

    @property
    def risk_level_label(self):
        return {'CRITICAL': 'Kritisch', 'HIGH': 'Hoch', 'MEDIUM': 'Mittel', 'LOW': 'Niedrig'}.get(self.risk_level, '–')

    # Legacy compatibility
    @property
    def severity(self):
        return self.impact

    def __str__(self):
        return self.title
