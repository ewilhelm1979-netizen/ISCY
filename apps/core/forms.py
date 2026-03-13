from django import forms


def _resolve_relation_path(obj, path):
    current = obj
    for part in path.split('__'):
        if current is None:
            return None
        current = getattr(current, part, None)
    return current


def _resolve_tenant_id(obj, tenant_path):
    tenant_ref = _resolve_relation_path(obj, tenant_path.replace('_id', ''))
    if tenant_ref is None and tenant_path.endswith('_id'):
        tenant_ref = _resolve_relation_path(obj, tenant_path)
    if tenant_ref is None:
        tenant_ref = _resolve_relation_path(obj, tenant_path)
    if hasattr(tenant_ref, 'pk'):
        return tenant_ref.pk
    return tenant_ref


class TenantScopedModelForm(forms.ModelForm):
    """Filtert FK-Felder tenant-spezifisch und validiert die Auswahl."""

    tenant_scoped_fields = {}

    def __init__(self, *args, tenant=None, **kwargs):
        self.tenant = tenant
        super().__init__(*args, **kwargs)
        self._apply_tenant_scope()

    def _apply_tenant_scope(self):
        for field_name, tenant_path in self.tenant_scoped_fields.items():
            field = self.fields.get(field_name)
            if field is None or not hasattr(field, 'queryset'):
                continue
            if self.tenant is None:
                field.queryset = field.queryset.none()
                continue
            queryset = field.queryset
            if tenant_path == 'tenant' and hasattr(queryset, 'for_tenant'):
                field.queryset = queryset.for_tenant(self.tenant)
            else:
                field.queryset = queryset.filter(**{tenant_path: self.tenant})

    def clean(self):
        cleaned_data = super().clean()
        if self.tenant is None:
            return cleaned_data
        for field_name, tenant_path in self.tenant_scoped_fields.items():
            value = cleaned_data.get(field_name)
            if value is None:
                continue
            related_tenant_id = _resolve_tenant_id(value, tenant_path)
            if related_tenant_id != self.tenant.pk:
                self.add_error(field_name, 'Objekt gehört zu einem anderen Mandanten.')
        return cleaned_data
