from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class InformationAsset(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'business_unit': 'tenant_id',
        'owner': 'tenant_id',
    }

    class Criticality(models.TextChoices):
        VERY_HIGH = 'VERY_HIGH', 'Sehr hoch'
        HIGH = 'HIGH', 'Hoch'
        MEDIUM = 'MEDIUM', 'Mittel'
        LOW = 'LOW', 'Niedrig'

    class Type(models.TextChoices):
        APPLICATION = 'APPLICATION', 'Anwendung'
        DATA = 'DATA', 'Datenbestand'
        INFRASTRUCTURE = 'INFRASTRUCTURE', 'Infrastruktur'
        SERVICE = 'SERVICE', 'Service / Plattform'
        DOCUMENT = 'DOCUMENT', 'Dokumentation'
        OTHER = 'OTHER', 'Sonstiges'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='information_assets')
    business_unit = models.ForeignKey('organizations.BusinessUnit', on_delete=models.SET_NULL, null=True, blank=True, related_name='information_assets')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_information_assets')
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=24, choices=Type.choices, default=Type.APPLICATION)
    criticality = models.CharField(max_length=16, choices=Criticality.choices, default=Criticality.MEDIUM)
    description = models.TextField(blank=True)
    confidentiality = models.CharField(max_length=32, blank=True)
    integrity = models.CharField(max_length=32, blank=True)
    availability = models.CharField(max_length=32, blank=True)
    lifecycle_status = models.CharField(max_length=64, blank=True)
    is_in_scope = models.BooleanField(default=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
