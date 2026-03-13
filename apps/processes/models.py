from django.db import models
from apps.core.models import TenantRelationValidationMixin, TimeStampedModel


class Process(TenantRelationValidationMixin, TimeStampedModel):
    tenant_relation_fields = {
        'business_unit': 'tenant_id',
        'owner': 'tenant_id',
    }

    class Status(models.TextChoices):
        SUFFICIENT = 'SUFFICIENT', 'Vorhanden und ausreichend'
        PARTIAL = 'PARTIAL', 'Vorhanden, aber unvollständig'
        INFORMAL = 'INFORMAL', 'Informal vorhanden'
        DOCUMENTED_NOT_IMPLEMENTED = 'DOCUMENTED_NOT_IMPLEMENTED', 'Dokumentiert, aber nicht umgesetzt'
        IMPLEMENTED_NO_EVIDENCE = 'IMPLEMENTED_NO_EVIDENCE', 'Umgesetzt, aber nicht nachweisbar'
        MISSING = 'MISSING', 'Fehlt vollständig'

    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.CASCADE, related_name='processes')
    business_unit = models.ForeignKey('organizations.BusinessUnit', on_delete=models.SET_NULL, null=True, blank=True, related_name='processes')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_processes')
    name = models.CharField(max_length=255)
    scope = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.MISSING)
    documented = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    communicated = models.BooleanField(default=False)
    implemented = models.BooleanField(default=False)
    effective = models.BooleanField(default=False)
    evidenced = models.BooleanField(default=False)
    reviewed_at = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
