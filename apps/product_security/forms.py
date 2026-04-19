from django import forms

from .models import ProductSecurityRoadmapTask


class ProductSecurityRoadmapTaskUpdateForm(forms.ModelForm):
    class Meta:
        model = ProductSecurityRoadmapTask
        fields = ['status', 'priority', 'owner_role', 'due_in_days', 'dependency_text']
        widgets = {
            'dependency_text': forms.Textarea(attrs={'rows': 3}),
        }
