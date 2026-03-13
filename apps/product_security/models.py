from django.db import models
from apps.core.models import TenantModel


class ProductFamily(TenantModel):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['name']
        unique_together = ('tenant', 'name')

    def __str__(self):
        return self.name


class Product(TenantModel):
    tenant_relation_fields = {
        'family': 'tenant_id',
    }

    family = models.ForeignKey(ProductFamily, on_delete=models.SET_NULL, null=True, blank=True, related_name='products')
    name = models.CharField(max_length=255)
    code = models.SlugField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    has_digital_elements = models.BooleanField(default=True)
    includes_ai = models.BooleanField(default=False)
    ot_iacs_context = models.BooleanField(default=False)
    automotive_context = models.BooleanField(default=False)
    support_window_months = models.PositiveIntegerField(default=24)
    regulatory_profile_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['name']
        unique_together = ('tenant', 'name')

    def __str__(self):
        return self.name


class ProductRelease(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
    }

    class Status(models.TextChoices):
        PLANNED = 'PLANNED', 'Geplant'
        ACTIVE = 'ACTIVE', 'Aktiv'
        MAINTENANCE = 'MAINTENANCE', 'Wartung'
        EOL = 'EOL', 'End of Life'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='releases')
    version = models.CharField(max_length=64)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PLANNED)
    release_date = models.DateField(null=True, blank=True)
    support_end_date = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['product__name', '-release_date', '-created_at']
        unique_together = ('product', 'version')

    def __str__(self):
        return f'{self.product.name} {self.version}'


class Component(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'supplier': 'tenant_id',
    }

    class Type(models.TextChoices):
        APPLICATION = 'APPLICATION', 'Application'
        LIBRARY = 'LIBRARY', 'Library'
        SERVICE = 'SERVICE', 'Service'
        MODEL = 'MODEL', 'AI Model'
        FIRMWARE = 'FIRMWARE', 'Firmware'
        OTHER = 'OTHER', 'Other'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='components')
    supplier = models.ForeignKey('organizations.Supplier', on_delete=models.SET_NULL, null=True, blank=True, related_name='product_components')
    name = models.CharField(max_length=255)
    component_type = models.CharField(max_length=16, choices=Type.choices, default=Type.APPLICATION)
    version = models.CharField(max_length=64, blank=True)
    is_open_source = models.BooleanField(default=False)
    has_sbom = models.BooleanField(default=False)

    class Meta:
        ordering = ['product__name', 'name']
        unique_together = ('product', 'name', 'version')

    def __str__(self):
        return f'{self.product.name}: {self.name}'


class AISystem(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
    }

    class RiskClass(models.TextChoices):
        NONE = 'NONE', 'Keine besondere AI-Risiko-Klasse'
        LIMITED = 'LIMITED', 'Begrenztes Risiko'
        HIGH = 'HIGH', 'High-Risk / erhöhte Governance'
        GPAI = 'GPAI', 'General Purpose AI / Modellbezug'

    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_systems')
    name = models.CharField(max_length=255)
    use_case = models.TextField(blank=True)
    provider = models.CharField(max_length=255, blank=True)
    risk_classification = models.CharField(max_length=16, choices=RiskClass.choices, default=RiskClass.NONE)
    in_scope = models.BooleanField(default=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class ThreatModel(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'release': 'tenant_id',
    }

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        REVIEW = 'REVIEW', 'Im Review'
        APPROVED = 'APPROVED', 'Freigegeben'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='threat_models')
    release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='threat_models')
    name = models.CharField(max_length=255)
    methodology = models.CharField(max_length=100, blank=True, default='STRIDE / ad hoc')
    summary = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)

    class Meta:
        ordering = ['product__name', 'name']

    def __str__(self):
        return self.name


class ThreatScenario(TenantModel):
    tenant_relation_fields = {
        'threat_model': 'tenant_id',
        'component': 'tenant_id',
    }

    class Category(models.TextChoices):
        SPOOFING = 'SPOOFING', 'Spoofing'
        TAMPERING = 'TAMPERING', 'Tampering'
        REPUDIATION = 'REPUDIATION', 'Repudiation'
        INFORMATION_DISCLOSURE = 'INFO_DISCLOSURE', 'Information Disclosure'
        DENIAL_OF_SERVICE = 'DOS', 'Denial of Service'
        ELEVATION = 'ELEVATION', 'Elevation of Privilege'
        SAFETY = 'SAFETY', 'Safety / Physical Impact'
        SUPPLY_CHAIN = 'SUPPLY_CHAIN', 'Supply Chain'
        AI_MISUSE = 'AI_MISUSE', 'AI Misuse / Model Risk'
        OTHER = 'OTHER', 'Other'

    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Kritisch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    threat_model = models.ForeignKey(ThreatModel, on_delete=models.CASCADE, related_name='scenarios')
    component = models.ForeignKey(Component, on_delete=models.SET_NULL, null=True, blank=True, related_name='threat_scenarios')
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=32, choices=Category.choices, default=Category.OTHER)
    attack_path = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    mitigation_status = models.CharField(max_length=64, blank=True, default='Open')

    class Meta:
        ordering = ['threat_model__product__name', 'severity', 'title']

    def __str__(self):
        return self.title


class TARA(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'release': 'tenant_id',
        'scenario': 'tenant_id',
    }

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        IN_REVIEW = 'IN_REVIEW', 'Im Review'
        ACCEPTED = 'ACCEPTED', 'Akzeptiert'
        MITIGATED = 'MITIGATED', 'Mitigiert'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='taras')
    release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='taras')
    scenario = models.ForeignKey(ThreatScenario, on_delete=models.SET_NULL, null=True, blank=True, related_name='taras')
    name = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    attack_feasibility = models.PositiveIntegerField(default=2)
    impact_score = models.PositiveIntegerField(default=2)
    risk_score = models.PositiveIntegerField(default=4)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    treatment_decision = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ['product__name', '-risk_score', 'name']

    def save(self, *args, **kwargs):
        self.risk_score = max(1, self.attack_feasibility) * max(1, self.impact_score)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Vulnerability(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'release': 'tenant_id',
        'component': 'tenant_id',
    }

    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Kritisch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        TRIAGED = 'TRIAGED', 'Triagiert'
        MITIGATED = 'MITIGATED', 'Mitigiert'
        FIXED = 'FIXED', 'Behoben'
        ACCEPTED = 'ACCEPTED', 'Akzeptiert'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='vulnerabilities')
    release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities')
    component = models.ForeignKey(Component, on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    cve = models.CharField(max_length=50, blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    remediation_due = models.DateField(null=True, blank=True)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['product__name', 'severity', 'title']

    def __str__(self):
        return self.title


class PSIRTCase(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'release': 'tenant_id',
        'vulnerability': 'tenant_id',
    }

    class Status(models.TextChoices):
        NEW = 'NEW', 'Neu'
        TRIAGE = 'TRIAGE', 'Triage'
        INVESTIGATING = 'INVESTIGATING', 'In Analyse'
        REMEDIATING = 'REMEDIATING', 'In Behebung'
        ADVISORY = 'ADVISORY', 'Advisory / Disclosure'
        CLOSED = 'CLOSED', 'Abgeschlossen'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='psirt_cases')
    release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='psirt_cases')
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.SET_NULL, null=True, blank=True, related_name='psirt_cases')
    case_id = models.CharField(max_length=64)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, choices=Vulnerability.Severity.choices, default=Vulnerability.Severity.MEDIUM)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    disclosure_due = models.DateField(null=True, blank=True)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['product__name', '-created_at']
        unique_together = ('tenant', 'case_id')

    def __str__(self):
        return self.case_id


class SecurityAdvisory(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'release': 'tenant_id',
        'psirt_case': 'tenant_id',
    }

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Entwurf'
        REVIEW = 'REVIEW', 'Im Review'
        PUBLISHED = 'PUBLISHED', 'Veröffentlicht'

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='advisories')
    release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='advisories')
    psirt_case = models.ForeignKey(PSIRTCase, on_delete=models.SET_NULL, null=True, blank=True, related_name='advisories')
    advisory_id = models.CharField(max_length=64)
    title = models.CharField(max_length=255)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    published_on = models.DateField(null=True, blank=True)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['product__name', '-created_at']
        unique_together = ('tenant', 'advisory_id')

    def __str__(self):
        return self.advisory_id


class ProductSecurityRoadmap(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
        'generated_from_snapshot': 'tenant_id',
    }

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='roadmaps')
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    generated_from_snapshot = models.ForeignKey('ProductSecuritySnapshot', on_delete=models.SET_NULL, null=True, blank=True, related_name='roadmaps')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class ProductSecurityRoadmapTask(TenantModel):
    tenant_relation_fields = {
        'roadmap': 'tenant_id',
        'related_release': 'tenant_id',
        'related_vulnerability': 'tenant_id',
    }

    class Phase(models.TextChoices):
        GOVERNANCE = 'GOVERNANCE', 'Governance'
        MODELING = 'MODELING', 'Threat Modeling / TARA'
        DELIVERY = 'DELIVERY', 'Secure Delivery'
        RESPONSE = 'RESPONSE', 'PSIRT / Response'
        COMPLIANCE = 'COMPLIANCE', 'Regulatory Readiness'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Offen'
        PLANNED = 'PLANNED', 'Geplant'
        IN_PROGRESS = 'IN_PROGRESS', 'In Umsetzung'
        DONE = 'DONE', 'Erledigt'

    roadmap = models.ForeignKey(ProductSecurityRoadmap, on_delete=models.CASCADE, related_name='tasks')
    related_release = models.ForeignKey(ProductRelease, on_delete=models.SET_NULL, null=True, blank=True, related_name='product_roadmap_tasks')
    related_vulnerability = models.ForeignKey(Vulnerability, on_delete=models.SET_NULL, null=True, blank=True, related_name='product_roadmap_tasks')
    phase = models.CharField(max_length=16, choices=Phase.choices, default=Phase.GOVERNANCE)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=32, blank=True)
    owner_role = models.CharField(max_length=64, blank=True)
    due_in_days = models.PositiveIntegerField(default=30)
    dependency_text = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)

    class Meta:
        ordering = ['phase', 'priority', 'title']

    def __str__(self):
        return self.title


class ProductSecuritySnapshot(TenantModel):
    tenant_relation_fields = {
        'product': 'tenant_id',
    }

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='snapshots')
    cra_applicable = models.BooleanField(default=False)
    ai_act_applicable = models.BooleanField(default=False)
    iec62443_applicable = models.BooleanField(default=False)
    iso_sae_21434_applicable = models.BooleanField(default=False)
    cra_readiness_percent = models.PositiveIntegerField(default=0)
    ai_act_readiness_percent = models.PositiveIntegerField(default=0)
    iec62443_readiness_percent = models.PositiveIntegerField(default=0)
    iso_sae_21434_readiness_percent = models.PositiveIntegerField(default=0)
    threat_model_coverage_percent = models.PositiveIntegerField(default=0)
    psirt_readiness_percent = models.PositiveIntegerField(default=0)
    open_vulnerability_count = models.PositiveIntegerField(default=0)
    critical_vulnerability_count = models.PositiveIntegerField(default=0)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'Snapshot {self.product.name} {self.created_at:%Y-%m-%d}'
