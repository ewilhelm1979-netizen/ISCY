from django import forms
from apps.core.forms import TenantScopedModelForm
from .models import InformationAsset


class InformationAssetForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'business_unit': 'tenant',
        'owner': 'tenant',
    }

    class Meta:
        model = InformationAsset
        fields = [
            'business_unit', 'owner', 'name', 'asset_type', 'criticality', 'description',
            'confidentiality', 'integrity', 'availability', 'lifecycle_status', 'is_in_scope'
        ]
