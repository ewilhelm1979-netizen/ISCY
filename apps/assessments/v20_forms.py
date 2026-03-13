"""V20: Forms fuer SoA, Audit, Management Review."""
from django import forms
from apps.core.forms import TenantScopedModelForm
from .soa_models import SoAEntry
from .audit_models import Audit, AuditFinding
from .review_models import ManagementReview, ReviewAction


class SoAEntryForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'control_owner': 'tenant',
    }

    class Meta:
        model = SoAEntry
        fields = ['is_applicable', 'justification', 'implementation_status', 'control_owner', 'evidence_reference', 'notes']
        widgets = {
            'justification': forms.Textarea(attrs={'rows': 2}),
            'evidence_reference': forms.Textarea(attrs={'rows': 2}),
            'notes': forms.Textarea(attrs={'rows': 2}),
        }


class AuditForm(TenantScopedModelForm):
    class Meta:
        model = Audit
        fields = ['title', 'audit_type', 'status', 'lead_auditor', 'audit_team', 'scope', 'objectives',
                  'planned_start', 'planned_end', 'actual_start', 'actual_end', 'conclusion']
        widgets = {
            'audit_team': forms.Textarea(attrs={'rows': 3}),
            'scope': forms.Textarea(attrs={'rows': 3}),
            'objectives': forms.Textarea(attrs={'rows': 2}),
            'conclusion': forms.Textarea(attrs={'rows': 3}),
            'planned_start': forms.DateInput(attrs={'type': 'date'}),
            'planned_end': forms.DateInput(attrs={'type': 'date'}),
            'actual_start': forms.DateInput(attrs={'type': 'date'}),
            'actual_end': forms.DateInput(attrs={'type': 'date'}),
        }


class AuditFindingForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'responsible': 'tenant',
    }

    class Meta:
        model = AuditFinding
        fields = ['finding_number', 'title', 'description', 'severity', 'status',
                  'requirement_reference', 'evidence_reference', 'responsible', 'due_date',
                  'root_cause', 'corrective_action', 'verification_notes']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'evidence_reference': forms.Textarea(attrs={'rows': 2}),
            'root_cause': forms.Textarea(attrs={'rows': 2}),
            'corrective_action': forms.Textarea(attrs={'rows': 3}),
            'verification_notes': forms.Textarea(attrs={'rows': 2}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }


class ManagementReviewForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'chairperson': 'tenant',
        'session': 'tenant',
    }

    class Meta:
        model = ManagementReview
        fields = [
            'title', 'status', 'review_date', 'chairperson', 'attendees', 'location',
            'input_isms_status', 'input_audit_results', 'input_risk_status',
            'input_incidents', 'input_metrics', 'input_feedback', 'input_improvement', 'input_changes',
            'output_decisions', 'output_actions', 'output_resource_needs', 'output_improvement',
            'protocol_summary', 'next_review_date',
        ]
        widgets = {k: forms.Textarea(attrs={'rows': 3}) for k in [
            'attendees', 'input_isms_status', 'input_audit_results', 'input_risk_status',
            'input_incidents', 'input_metrics', 'input_feedback', 'input_improvement', 'input_changes',
            'output_decisions', 'output_actions', 'output_resource_needs', 'output_improvement',
            'protocol_summary',
        ]}
        widgets['review_date'] = forms.DateInput(attrs={'type': 'date'})
        widgets['next_review_date'] = forms.DateInput(attrs={'type': 'date'})


class ReviewActionForm(TenantScopedModelForm):
    tenant_scoped_fields = {
        'responsible': 'tenant',
    }

    class Meta:
        model = ReviewAction
        fields = ['title', 'description', 'responsible', 'due_date', 'status', 'completion_notes']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
            'completion_notes': forms.Textarea(attrs={'rows': 2}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }
