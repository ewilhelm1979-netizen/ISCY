from django import forms
from apps.core.forms import TenantScopedModelForm
from .models import Risk


class RiskForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'category': 'tenant',
        'process': 'tenant',
        'asset': 'tenant',
        'owner': 'tenant',
    }

    class Meta:
        model = Risk
        fields = [
            'title', 'description', 'category', 'process', 'asset', 'owner',
            'threat', 'vulnerability', 'impact', 'likelihood',
            'residual_impact', 'residual_likelihood',
            'status', 'treatment_strategy', 'treatment_plan', 'treatment_due_date',
            'review_date',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'threat': forms.Textarea(attrs={'rows': 2}),
            'vulnerability': forms.Textarea(attrs={'rows': 2}),
            'treatment_plan': forms.Textarea(attrs={'rows': 3}),
            'treatment_due_date': forms.DateInput(attrs={'type': 'date'}),
            'review_date': forms.DateInput(attrs={'type': 'date'}),
        }
