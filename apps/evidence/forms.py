from django import forms
from .models import EvidenceItem


class EvidenceItemForm(forms.ModelForm):
    class Meta:
        model = EvidenceItem
        fields = ['title', 'description', 'requirement', 'linked_requirement', 'domain', 'measure', 'file', 'status', 'review_notes']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'review_notes': forms.Textarea(attrs={'rows': 3}),
        }
