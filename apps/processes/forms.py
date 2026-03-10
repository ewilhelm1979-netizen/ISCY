from django import forms
from .models import Process


class ProcessForm(forms.ModelForm):
    class Meta:
        model = Process
        fields = [
            'tenant', 'business_unit', 'owner', 'name', 'scope', 'description', 'status',
            'documented', 'approved', 'communicated', 'implemented', 'effective', 'evidenced', 'reviewed_at'
        ]
        widgets = {
            'reviewed_at': forms.DateInput(attrs={'type': 'date'}),
        }
