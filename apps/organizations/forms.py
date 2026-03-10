from django import forms
from .models import Tenant
from .country_catalog import COUNTRY_CHOICES


class TenantForm(forms.ModelForm):
    countries = forms.MultipleChoiceField(
        label='Länder / operative Präsenz',
        required=False,
        choices=COUNTRY_CHOICES,
        widget=forms.SelectMultiple(attrs={'class': 'form-select', 'size': 10}),
    )

    class Meta:
        model = Tenant
        fields = [
            'name', 'slug', 'sector', 'employee_count', 'annual_revenue_million', 'balance_sheet_million',
            'critical_services', 'supply_chain_role', 'description', 'nis2_relevant', 'kritis_relevant',
            'develops_digital_products', 'uses_ai_systems', 'ot_iacs_scope', 'automotive_scope',
            'psirt_defined', 'sbom_required', 'product_security_scope',
        ]
        widgets = {
            'critical_services': forms.Textarea(attrs={'rows': 3}),
            'description': forms.Textarea(attrs={'rows': 4}),
            'product_security_scope': forms.Textarea(attrs={'rows': 4}),
            'sector': forms.Select(attrs={'class': 'form-select'}),
        }
        help_texts = {
            'develops_digital_products': 'Aktivieren, wenn Produkte mit digitalen Elementen oder softwareintensive Produkte entwickelt werden.',
            'uses_ai_systems': 'Aktivieren, wenn AI-Systeme/Modelle/Funktionen im Scope sind.',
            'ot_iacs_scope': 'Aktivieren für OT-/IACS-/Industrieprodukte oder Integrationskontexte.',
            'automotive_scope': 'Aktivieren für Automotive-/Fahrzeug-/E/E-bezogene Entwicklung.',
            'psirt_defined': 'Aktivieren, wenn ein PSIRT-/Vulnerability-Handling bereits existiert.',
            'sbom_required': 'Aktivieren, wenn SBOM/Komponenten-Transparenz relevant ist oder gefordert wird.',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['countries'].initial = self.instance.operation_countries or ([self.instance.country] if self.instance.country else [])

    def save(self, commit=True):
        tenant = super().save(commit=False)
        selected_countries = self.cleaned_data.get('countries') or []
        tenant.operation_countries = selected_countries
        tenant.country = selected_countries[0] if selected_countries else ''
        if commit:
            tenant.save()
        return tenant
