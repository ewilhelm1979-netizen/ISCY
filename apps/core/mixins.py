"""F14: Zentrale Autorisierungspruefung auf Objektebene.

TenantAccessMixin stellt sicher, dass eingeloggte User nur auf
Objekte ihres eigenen Tenants zugreifen koennen.
"""
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied


class TenantAccessMixin(LoginRequiredMixin):
    """Mixin das Login + Tenant-Zugriffspruefung kombiniert.

    Views die get_object() nutzen (DetailView, UpdateView etc.) werden
    automatisch geprueft. Fuer andere Views kann check_tenant_access()
    manuell aufgerufen werden.
    """

    def get_queryset(self):
        qs = super().get_queryset()
        if hasattr(qs, 'for_tenant'):
            return qs.for_tenant(self.request.tenant)
        if hasattr(qs.model, 'tenant'):
            return qs.filter(tenant=self.request.tenant)
        return qs

    def check_tenant_access(self, obj):
        """Prueft ob das Objekt zum Tenant des Request-Users gehoert."""
        if self.request.tenant is None:
            raise PermissionDenied('Kein Tenant zugeordnet.')
        obj_tenant = getattr(obj, 'tenant', None) or getattr(obj, 'tenant_id', None)
        if obj_tenant is None:
            return  # Kein Tenant-bezogenes Objekt
        tenant_id = obj_tenant if isinstance(obj_tenant, int) else getattr(obj_tenant, 'pk', None)
        if tenant_id != self.request.tenant.pk:
            raise PermissionDenied('Kein Zugriff auf diesen Mandanten.')

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        self.check_tenant_access(obj)
        return obj
