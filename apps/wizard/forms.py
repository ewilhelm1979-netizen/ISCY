from django import forms
from apps.organizations.models import Tenant
from apps.organizations.country_catalog import COUNTRY_CHOICES
from apps.organizations.sector_catalog import SECTOR_CHOICES
from .models import AssessmentSession


class AssessmentLaunchForm(forms.Form):
    assessment_type = forms.ChoiceField(
        choices=AssessmentSession.Type.choices,
        label='Art des Assessments',
        widget=forms.RadioSelect,
    )
    sector = forms.ChoiceField(
        choices=SECTOR_CHOICES,
        label='Sektor',
        required=True,
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text='Die Sektorauswahl wirkt auf Betroffenheitsprüfung, Schwerpunktdomänen, Maßnahmen und Roadmap.',
    )
    countries = forms.MultipleChoiceField(
        label='Operative Länder',
        required=False,
        choices=COUNTRY_CHOICES,
        widget=forms.SelectMultiple(attrs={'class': 'form-select', 'size': 8}),
        help_text='Mehrfachauswahl möglich. Länder wirken auf Governance, Incident-Koordination und Drittlandprüfung.',
    )


class CompanyProfileForm(forms.ModelForm):
    annual_revenue_million = forms.DecimalField(label='Jahresumsatz in Mio. €', max_digits=10, decimal_places=2, required=False)
    balance_sheet_million = forms.DecimalField(label='Bilanzsumme in Mio. €', max_digits=10, decimal_places=2, required=False)
    countries = forms.MultipleChoiceField(
        label='Länder / operative Präsenz',
        required=False,
        choices=COUNTRY_CHOICES,
        widget=forms.SelectMultiple(attrs={'class': 'form-select', 'size': 10}),
        help_text='Mehrfachauswahl möglich. Diese Auswahl beeinflusst Betroffenheitsindikation, grenzüberschreitende Governance, Incident-Koordination und Roadmap.',
    )

    class Meta:
        model = Tenant
        fields = [
            'name', 'slug', 'sector', 'employee_count', 'annual_revenue_million', 'balance_sheet_million',
            'critical_services', 'supply_chain_role', 'description',
            'develops_digital_products', 'uses_ai_systems', 'ot_iacs_scope', 'automotive_scope',
            'psirt_defined', 'sbom_required', 'product_security_scope',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'critical_services': forms.Textarea(attrs={'rows': 3}),
            'product_security_scope': forms.Textarea(attrs={'rows': 4}),
            'sector': forms.Select(attrs={'class': 'form-select'}),
        }
        help_texts = {
            'sector': 'Wähle den in Deutschland passenden NIS2-/KRITIS-nahen Sektor. Diese Auswahl beeinflusst Betroffenheitsindikation, Schwerpunktdomänen und Roadmap.',
            'develops_digital_products': 'Für Produkte mit digitalen Elementen / Softwareprodukte aktivieren.',
            'uses_ai_systems': 'Für AI-Systeme, AI-Komponenten oder AI-gestützte Produktfunktionen aktivieren.',
            'ot_iacs_scope': 'Für OT-/IACS-/Industrie- oder Anlagenkontexte aktivieren.',
            'automotive_scope': 'Für Automotive-/Fahrzeug-/E/E-Kontexte aktivieren.',
            'psirt_defined': 'Aktivieren, wenn bereits ein PSIRT-/Vulnerability-Handling-Prozess existiert.',
            'sbom_required': 'Aktivieren, wenn SBOM-/Komponenten-Transparenz benötigt oder gefordert wird.',
            'product_security_scope': 'Optionaler Scope-Text für Produkte, Releases, AI-Systeme, OT-/Automotive-Kontext oder Support-/Patch-Verantwortung.',
        }


class ScopeCaptureForm(forms.Form):
    scope_statement = forms.CharField(label='ISMS-Scope', widget=forms.Textarea(attrs={'rows': 4}), required=False)
    business_units = forms.CharField(label='Geschäftsbereiche', required=False, widget=forms.Textarea(attrs={'rows': 4}), help_text='Je Zeile ein Geschäftsbereich')
    processes = forms.CharField(label='Kritische Prozesse', required=False, widget=forms.Textarea(attrs={'rows': 6}), help_text='Je Zeile ein Prozess')
    suppliers = forms.CharField(label='Kritische Dienstleister / Lieferanten', required=False, widget=forms.Textarea(attrs={'rows': 4}), help_text='Je Zeile ein Lieferant')
