from django import forms
from apps.core.forms import TenantScopedModelForm
from .models import ApplicabilityAssessment, Assessment, Measure


class ApplicabilityAssessmentForm(TenantScopedModelForm):
    class Meta:
        model = ApplicabilityAssessment
        fields = ['sector', 'company_size', 'critical_services', 'supply_chain_role', 'status', 'reasoning']


class AssessmentForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'process': 'tenant',
        'owner': 'tenant',
    }

    class Meta:
        model = Assessment
        fields = ['process', 'requirement', 'owner', 'status', 'score', 'notes', 'evidence_summary']


class MeasureForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'assessment': 'tenant',
        'owner': 'tenant',
    }

    class Meta:
        model = Measure
        fields = ['assessment', 'owner', 'title', 'description', 'priority', 'status', 'due_date']
        widgets = {
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }
