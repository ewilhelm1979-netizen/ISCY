from django.conf import settings
from django.db import models


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# --- F09: TenantQuerySet / TenantManager ---

class TenantQuerySet(models.QuerySet):
    """QuerySet das automatisch nach Tenant filtert."""
    def for_tenant(self, tenant):
        if tenant is None:
            return self.none()
        return self.filter(tenant=tenant)


class TenantManager(models.Manager):
    def get_queryset(self):
        return TenantQuerySet(self.model, using=self._db)

    def for_tenant(self, tenant):
        return self.get_queryset().for_tenant(tenant)


class TenantModel(TimeStampedModel):
    """Abstrakte Basis fuer alle mandantenbezogenen Models.

    Stellt sicher, dass ein TenantManager vorhanden ist und der
    Tenant-FK immer gesetzt wird.
    """
    tenant = models.ForeignKey(
        'organizations.Tenant',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)ss',
    )

    objects = TenantManager()

    class Meta:
        abstract = True


# --- F10: Audit-Trail ---

class AuditLog(models.Model):
    """Zentraler Audit-Trail fuer revisionssichere Protokollierung."""

    class Action(models.TextChoices):
        CREATE = 'CREATE', 'Erstellt'
        UPDATE = 'UPDATE', 'Geaendert'
        DELETE = 'DELETE', 'Geloescht'
        STATUS_CHANGE = 'STATUS_CHANGE', 'Status geaendert'
        LOGIN = 'LOGIN', 'Login'
        EXPORT = 'EXPORT', 'Export'

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='audit_logs',
    )
    tenant = models.ForeignKey(
        'organizations.Tenant',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='audit_logs',
    )
    action = models.CharField(max_length=20, choices=Action.choices)
    entity_type = models.CharField(max_length=128, db_index=True)
    entity_id = models.PositiveBigIntegerField(null=True, blank=True)
    entity_label = models.CharField(max_length=255, blank=True)
    changes_json = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    extra = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', '-timestamp']),
            models.Index(fields=['entity_type', 'entity_id']),
        ]

    def __str__(self):
        return f'{self.timestamp} {self.action} {self.entity_type}#{self.entity_id}'

    @classmethod
    def log(cls, *, request=None, user=None, tenant=None, action, entity, changes=None, extra=None):
        _user = user or (getattr(request, 'user', None) if request else None)
        _tenant = tenant or (getattr(request, 'tenant', None) if request else None)
        ip = None
        if request:
            ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', ''))
            if ',' in (ip or ''):
                ip = ip.split(',')[0].strip()
        return cls.objects.create(
            user=_user if (_user and getattr(_user, 'is_authenticated', False)) else None,
            tenant=_tenant,
            action=action,
            entity_type=entity.__class__.__name__,
            entity_id=getattr(entity, 'pk', None),
            entity_label=str(entity)[:255],
            changes_json=changes or {},
            ip_address=ip or None,
            extra=extra or {},
        )
