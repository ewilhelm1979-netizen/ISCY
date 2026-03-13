from django import forms
from apps.core.forms import TenantScopedModelForm
from .models import EvidenceItem


class EvidenceItemForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'session': 'tenant',
        'measure': 'session__tenant',
    }

    class Meta:
        model = EvidenceItem
        fields = ['title', 'description', 'requirement', 'linked_requirement', 'domain', 'measure', 'file', 'status', 'review_notes']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'review_notes': forms.Textarea(attrs={'rows': 3}),
        }
