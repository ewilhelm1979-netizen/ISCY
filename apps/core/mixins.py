"""F14: Zentrale Autorisierungspruefung auf Objektebene.

TenantAccessMixin stellt sicher, dass eingeloggte User nur auf
Objekte ihres eigenen Tenants zugreifen koennen.
"""
import inspect

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied


class TenantAccessMixin(LoginRequiredMixin):
    """Mixin das Login + Tenant-Zugriffspruefung kombiniert.

    Views die get_object() nutzen (DetailView, UpdateView etc.) werden
    automatisch geprueft. Fuer andere Views kann check_tenant_access()
    manuell aufgerufen werden.
    """

    tenant_filter_field = 'tenant'

    def get_tenant(self):
        return getattr(self.request, 'tenant', None)

    def filter_queryset_for_tenant(self, qs):
        tenant = self.get_tenant()
        tenant_filter_field = getattr(self, 'tenant_filter_field', 'tenant')
        if tenant is None:
            return qs.none()
        if tenant_filter_field == 'tenant' and hasattr(qs, 'for_tenant'):
            return qs.for_tenant(tenant)
        if tenant_filter_field:
            return qs.filter(**{tenant_filter_field: tenant})
        return qs

    def get_queryset(self):
        return self.filter_queryset_for_tenant(super().get_queryset())

    def check_tenant_access(self, obj):
        """Prueft ob das Objekt zum Tenant des Request-Users gehoert."""
        tenant = self.get_tenant()
        if tenant is None:
            raise PermissionDenied('Kein Tenant zugeordnet.')
        current = obj
        for part in self.tenant_filter_field.split('__'):
            current = getattr(current, part, None)
            if current is None:
                break
        obj_tenant = current or getattr(obj, 'tenant', None) or getattr(obj, 'tenant_id', None)
        if obj_tenant is None:
            return  # Kein Tenant-bezogenes Objekt
        tenant_id = obj_tenant if isinstance(obj_tenant, int) else getattr(obj_tenant, 'pk', None)
        if tenant_id != tenant.pk:
            raise PermissionDenied('Kein Zugriff auf diesen Mandanten.')

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        self.check_tenant_access(obj)
        return obj

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        form_class = self.get_form_class()
        init_signature = inspect.signature(form_class.__init__)
        accepts_tenant = 'tenant' in init_signature.parameters
        if accepts_tenant:
            kwargs.setdefault('tenant', self.get_tenant())
        return kwargs


class TenantCreateMixin(TenantAccessMixin):
    """Setzt den Tenant serverseitig vor dem Speichern."""

    def form_valid(self, form):
        if hasattr(form.instance, 'tenant_id'):
            form.instance.tenant = self.get_tenant()
        return super().form_valid(form)
