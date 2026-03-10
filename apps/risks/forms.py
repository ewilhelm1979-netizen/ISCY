from django import forms
from .models import Risk


class RiskForm(forms.ModelForm):
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
