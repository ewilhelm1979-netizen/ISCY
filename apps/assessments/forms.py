from django import forms
from .models import ApplicabilityAssessment, Assessment, Measure


class ApplicabilityAssessmentForm(forms.ModelForm):
    class Meta:
        model = ApplicabilityAssessment
        fields = ['tenant', 'sector', 'company_size', 'critical_services', 'supply_chain_role', 'status', 'reasoning']


class AssessmentForm(forms.ModelForm):
    class Meta:
        model = Assessment
        fields = ['tenant', 'process', 'requirement', 'owner', 'status', 'score', 'notes', 'evidence_summary']


class MeasureForm(forms.ModelForm):
    class Meta:
        model = Measure
        fields = ['tenant', 'assessment', 'owner', 'title', 'description', 'priority', 'status', 'due_date']
        widgets = {
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }
