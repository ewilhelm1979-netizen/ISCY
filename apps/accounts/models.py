from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.Model):
    """F18: Eigenstaendiges Role-Model fuer M2M-Beziehungen."""
    class Code(models.TextChoices):
        MANAGEMENT = 'MANAGEMENT', 'Management'
        CISO = 'CISO', 'CISO / Security Officer'
        ISMS_MANAGER = 'ISMS_MANAGER', 'ISMS Manager'
        COMPLIANCE_MANAGER = 'COMPLIANCE_MANAGER', 'Compliance Manager'
        PROCESS_OWNER = 'PROCESS_OWNER', 'Process Owner'
        RISK_OWNER = 'RISK_OWNER', 'Risk Owner'
        AUDITOR = 'AUDITOR', 'Auditor'
        ADMIN = 'ADMIN', 'Administrator'
        CONTRIBUTOR = 'CONTRIBUTOR', 'Contributor'

    code = models.CharField(max_length=32, choices=Code.choices, unique=True)
    label = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['code']

    def __str__(self):
        return self.label


class User(AbstractUser):
    # F18: Beibehalten fuer Abwaertskompatibilitaet, wird durch roles M2M ergaenzt
    class LegacyRole(models.TextChoices):
        MANAGEMENT = 'MANAGEMENT', 'Management'
        CISO = 'CISO', 'CISO / Security Officer'
        ISMS_MANAGER = 'ISMS_MANAGER', 'ISMS Manager'
        COMPLIANCE_MANAGER = 'COMPLIANCE_MANAGER', 'Compliance Manager'
        PROCESS_OWNER = 'PROCESS_OWNER', 'Process Owner'
        RISK_OWNER = 'RISK_OWNER', 'Risk Owner'
        AUDITOR = 'AUDITOR', 'Auditor'
        ADMIN = 'ADMIN', 'Administrator'
        CONTRIBUTOR = 'CONTRIBUTOR', 'Contributor'

    role = models.CharField(max_length=32, choices=LegacyRole.choices, default=LegacyRole.CONTRIBUTOR,
                            help_text='Deprecated: Nutze roles M2M stattdessen.')
    tenant = models.ForeignKey('organizations.Tenant', on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    job_title = models.CharField(max_length=255, blank=True)

    # F18: M2M Rollen mit optionalem Scope
    roles = models.ManyToManyField(Role, through='UserRole', through_fields=('user', 'role'), blank=True, related_name='users')

    def __str__(self):
        return self.get_full_name() or self.username

    def has_role(self, role_code, scope_tenant=None):
        """Prueft ob der User eine bestimmte Rolle hat (optional im Scope eines Tenants)."""
        qs = self.user_roles.filter(role__code=role_code)
        if scope_tenant:
            qs = qs.filter(models.Q(scope_tenant=scope_tenant) | models.Q(scope_tenant__isnull=True))
        return qs.exists()

    @property
    def role_codes(self):
        """Alle Rollencodes dieses Users."""
        codes = set(self.user_roles.values_list('role__code', flat=True))
        if self.role and self.role not in codes:
            codes.add(self.role)
        return codes


class UserRole(models.Model):
    """F18: Zuordnung User <-> Rolle mit optionalem Tenant-Scope."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    scope_tenant = models.ForeignKey(
        'organizations.Tenant', on_delete=models.CASCADE,
        null=True, blank=True, related_name='scoped_user_roles',
        help_text='Optional: Rolle gilt nur fuer diesen Tenant. Leer = global.',
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='granted_roles')

    class Meta:
        unique_together = ('user', 'role', 'scope_tenant')
        ordering = ['user', 'role']

    def __str__(self):
        scope = f' ({self.scope_tenant})' if self.scope_tenant else ''
        return f'{self.user} -> {self.role}{scope}'
