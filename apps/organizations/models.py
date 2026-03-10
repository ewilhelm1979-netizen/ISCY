from django.db import models
from apps.core.models import TimeStampedModel
from .sector_catalog import SECTOR_CHOICES, get_sector_definition
from .country_catalog import get_country_labels


class Tenant(TimeStampedModel):
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    country = models.CharField(max_length=100, blank=True)
    operation_countries = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    sector = models.CharField(max_length=64, blank=True, choices=SECTOR_CHOICES, default='OTHER')
    employee_count = models.PositiveIntegerField(default=0)
    annual_revenue_million = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    balance_sheet_million = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    critical_services = models.TextField(blank=True)
    supply_chain_role = models.CharField(max_length=255, blank=True)
    nis2_relevant = models.BooleanField(default=False)
    kritis_relevant = models.BooleanField(default=False)

    # Product-security / software-development context
    develops_digital_products = models.BooleanField(default=False)
    uses_ai_systems = models.BooleanField(default=False)
    ot_iacs_scope = models.BooleanField(default=False)
    automotive_scope = models.BooleanField(default=False)
    psirt_defined = models.BooleanField(default=False)
    sbom_required = models.BooleanField(default=False)
    product_security_scope = models.TextField(blank=True)

    def __str__(self):
        return self.name

    @property
    def country_labels(self):
        codes = self.operation_countries or ([self.country] if self.country else [])
        return get_country_labels(codes)

    @property
    def countries_display(self):
        labels = self.country_labels
        return ", ".join(labels) if labels else "-"

    @property
    def sector_profile(self):
        return get_sector_definition(self.sector)

    @property
    def sector_label(self):
        return self.sector_profile.label

    @property
    def product_security_summary(self):
        if not self.develops_digital_products and not any([self.uses_ai_systems, self.ot_iacs_scope, self.automotive_scope]):
            return 'Kein ausgeprägter Product-Security-Scope angegeben.'
        active = []
        if self.develops_digital_products:
            active.append('CRA/Product Security')
        if self.uses_ai_systems:
            active.append('AI Act / AI Governance')
        if self.ot_iacs_scope:
            active.append('IEC 62443 / OT')
        if self.automotive_scope:
            active.append('ISO/SAE 21434 / Automotive')
        return 'Aktive Product-Security-Kontexte: ' + ', '.join(active)


class LegalEntity(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='legal_entities')
    name = models.CharField(max_length=255)
    country = models.CharField(max_length=100)
    registration_number = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.name


class BusinessUnit(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='business_units')
    name = models.CharField(max_length=255)
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_business_units')

    def __str__(self):
        return self.name


class Site(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='sites')
    legal_entity = models.ForeignKey(LegalEntity, on_delete=models.CASCADE, related_name='sites')
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True)
    country = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Supplier(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='suppliers')
    name = models.CharField(max_length=255)
    service_description = models.TextField(blank=True)
    criticality = models.CharField(max_length=32, default='MEDIUM')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_suppliers')

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
