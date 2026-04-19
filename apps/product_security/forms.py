from django import forms

from .models import ProductSecurityRoadmapTask, Vulnerability


class ProductSecurityRoadmapTaskUpdateForm(forms.ModelForm):
    class Meta:
        model = ProductSecurityRoadmapTask
        fields = ['status', 'priority', 'owner_role', 'due_in_days', 'dependency_text']
        widgets = {
            'dependency_text': forms.Textarea(attrs={'rows': 3}),
        }


class ProductSecurityVulnerabilityUpdateForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = ['severity', 'status', 'remediation_due', 'summary']
        widgets = {
            'remediation_due': forms.DateInput(attrs={'type': 'date'}),
            'summary': forms.Textarea(attrs={'rows': 4}),
        }
