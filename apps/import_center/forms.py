
from django import forms
from django.db import models


class DataImportForm(forms.Form):
    class ImportType(models.TextChoices):
        BUSINESS_UNITS = 'business_units', 'Geschäftsbereiche'
        PROCESSES = 'processes', 'Prozesse'
        SUPPLIERS = 'suppliers', 'Dienstleister / Lieferanten'
        ASSETS = 'assets', 'Informationswerte / Anwendungen'

    import_type = forms.ChoiceField(choices=ImportType.choices, label='Importtyp')
    file = forms.FileField(label='CSV oder XLSX-Datei')
    replace_existing = forms.BooleanField(required=False, initial=False, label='Bestehende Einträge dieses Typs vor dem Import löschen')
