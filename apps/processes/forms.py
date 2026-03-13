from django import forms
from apps.core.forms import TenantScopedModelForm
from .models import Process


class ProcessForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'business_unit': 'tenant',
        'owner': 'tenant',
    }

    class Meta:
        model = Process
        fields = [
            'business_unit', 'owner', 'name', 'scope', 'description', 'status',
            'documented', 'approved', 'communicated', 'implemented', 'effective', 'evidenced', 'reviewed_at'
        ]
        widgets = {
            'reviewed_at': forms.DateInput(attrs={'type': 'date'}),
        }
