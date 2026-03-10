
from django import forms
from .models import InformationAsset


class InformationAssetForm(forms.ModelForm):
    class Meta:
        model = InformationAsset
        fields = [
            'tenant', 'business_unit', 'owner', 'name', 'asset_type', 'criticality', 'description',
            'confidentiality', 'integrity', 'availability', 'lifecycle_status', 'is_in_scope'
        ]
