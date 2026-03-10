from django import forms
from .models import RoadmapTask


class RoadmapTaskUpdateForm(forms.ModelForm):
    class Meta:
        model = RoadmapTask
        fields = ['status', 'planned_start', 'due_date', 'owner_role', 'notes']
        widgets = {
            'planned_start': forms.DateInput(attrs={'type': 'date'}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }
