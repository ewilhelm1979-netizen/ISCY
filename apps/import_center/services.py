import csv
import io
from pathlib import Path
from typing import Iterable, List, Tuple

from openpyxl import load_workbook

from apps.assets_app.models import InformationAsset
from apps.organizations.models import BusinessUnit, Supplier
from apps.processes.models import Process


TRUE_VALUES = {"1", "true", "yes", "ja", "y"}

COLUMN_SYNONYMS = {
    'name': ['Name'],
    'owner_email': ['OwnerEmail', 'Verantwortlicher'],
    'scope': ['Scope'],
    'description': ['Beschreibung', 'Service'],
    'status': ['Status'],
    'business_unit': ['BusinessUnit', 'Geschäftsbereich'],
    'documented': ['Dokumentiert'],
    'implemented': ['Umgesetzt'],
    'evidenced': ['Nachweisbar'],
    'approved': ['Genehmigt'],
    'communicated': ['Kommuniziert'],
    'effective': ['Wirksam'],
    'service_description': ['Beschreibung', 'Service'],
    'criticality': ['Kritikalität'],
    'asset_type': ['Typ'],
    'confidentiality': ['Vertraulichkeit'],
    'integrity': ['Integrität'],
    'availability': ['Verfügbarkeit'],
    'lifecycle_status': ['Lifecycle'],
    'in_scope': ['ImScope'],
}

TEMPLATE_COLUMNS = {
    'business_units': ['name', 'owner_email'],
    'processes': ['name', 'scope', 'description', 'status', 'business_unit', 'documented', 'implemented', 'evidenced', 'approved', 'communicated', 'effective'],
    'suppliers': ['name', 'service_description', 'criticality'],
    'assets': ['name', 'asset_type', 'criticality', 'description', 'business_unit', 'confidentiality', 'integrity', 'availability', 'lifecycle_status', 'in_scope'],
}


class ImportService:
    @staticmethod
    def read_rows(uploaded_file) -> Tuple[List[str], List[dict]]:
        suffix = Path(uploaded_file.name).suffix.lower()
        if suffix == '.csv':
            data = uploaded_file.read().decode('utf-8-sig')
            reader = csv.DictReader(io.StringIO(data))
            rows = [row for row in reader]
            return reader.fieldnames or [], rows
        if suffix in {'.xlsx', '.xlsm'}:
            wb = load_workbook(uploaded_file, read_only=True, data_only=True)
            ws = wb.active
            values = list(ws.iter_rows(values_only=True))
            if not values:
                return [], []
            headers = [str(v).strip() if v is not None else '' for v in values[0]]
            rows = []
            for row in values[1:]:
                item = {}
                for idx, header in enumerate(headers):
                    item[header] = row[idx] if idx < len(row) else None
                rows.append(item)
            return headers, rows
        raise ValueError('Nur CSV oder XLSX werden unterstützt.')

    @staticmethod
    def bool_value(value) -> bool:
        return str(value).strip().lower() in TRUE_VALUES

    @staticmethod
    def normalize(value):
        return str(value).strip() if value is not None else ''

    @staticmethod
    def expected_columns(import_type: str):
        return TEMPLATE_COLUMNS.get(import_type, [])

    @staticmethod
    def default_mapping(import_type: str, headers: list[str]):
        expected = ImportService.expected_columns(import_type)
        normalized = {str(h).strip().lower(): h for h in headers}
        mapping = {}
        for canonical in expected:
            matched = normalized.get(canonical.lower())
            if not matched:
                for synonym in COLUMN_SYNONYMS.get(canonical, []):
                    if synonym.lower() in normalized:
                        matched = normalized[synonym.lower()]
                        break
            mapping[canonical] = matched or ''
        return mapping

    @staticmethod
    def get_mapping_preview(import_type: str, headers: list[str], selected_mapping: dict | None = None):
        expected = TEMPLATE_COLUMNS.get(import_type, [])
        selected_mapping = selected_mapping or ImportService.default_mapping(import_type, headers)
        rows = []
        selected_values = {str(v).strip().lower() for v in selected_mapping.values() if v}
        extra_headers = [h for h in headers if str(h).strip().lower() not in selected_values]
        for canonical in expected:
            matched = selected_mapping.get(canonical, '')
            rows.append({
                'expected': canonical,
                'matched': matched,
                'status': 'ok' if matched else 'missing',
                'synonyms': COLUMN_SYNONYMS.get(canonical, []),
                'required': canonical == 'name',
            })
        return rows, extra_headers

    @staticmethod
    def apply_mapping(rows: list[dict], selected_mapping: dict):
        transformed = []
        for row in rows:
            out = {}
            for expected, source in selected_mapping.items():
                out[expected] = row.get(source) if source else None
            transformed.append(out)
        return transformed

    @staticmethod
    def import_business_units(tenant, rows: Iterable[dict], replace_existing=False):
        if replace_existing:
            BusinessUnit.objects.filter(tenant=tenant).delete()
        created = updated = 0
        for row in rows:
            name = ImportService.normalize(row.get('name') or row.get('Name'))
            if not name:
                continue
            _, was_created = BusinessUnit.objects.update_or_create(
                tenant=tenant,
                name=name,
                defaults={},
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated

    @staticmethod
    def import_processes(tenant, rows: Iterable[dict], replace_existing=False):
        if replace_existing:
            Process.objects.filter(tenant=tenant).delete()
        created = updated = 0
        status_map = {choice[0].lower(): choice[0] for choice in Process.Status.choices}
        for row in rows:
            name = ImportService.normalize(row.get('name') or row.get('Name'))
            if not name:
                continue
            scope = ImportService.normalize(row.get('scope') or row.get('Scope'))
            description = ImportService.normalize(row.get('description') or row.get('Beschreibung'))
            status_raw = ImportService.normalize(row.get('status') or row.get('Status')).lower()
            status = status_map.get(status_raw, Process.Status.MISSING)
            business_unit_name = ImportService.normalize(row.get('business_unit') or row.get('BusinessUnit') or row.get('Geschäftsbereich'))
            business_unit = None
            if business_unit_name:
                business_unit, _ = BusinessUnit.objects.get_or_create(tenant=tenant, name=business_unit_name)
            obj, was_created = Process.objects.update_or_create(
                tenant=tenant,
                name=name,
                defaults={
                    'scope': scope,
                    'description': description,
                    'status': status,
                    'business_unit': business_unit,
                    'documented': ImportService.bool_value(row.get('documented') or row.get('Dokumentiert')),
                    'implemented': ImportService.bool_value(row.get('implemented') or row.get('Umgesetzt')),
                    'evidenced': ImportService.bool_value(row.get('evidenced') or row.get('Nachweisbar')),
                    'approved': ImportService.bool_value(row.get('approved') or row.get('Genehmigt')),
                    'communicated': ImportService.bool_value(row.get('communicated') or row.get('Kommuniziert')),
                    'effective': ImportService.bool_value(row.get('effective') or row.get('Wirksam')),
                },
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated

    @staticmethod
    def import_suppliers(tenant, rows: Iterable[dict], replace_existing=False):
        if replace_existing:
            Supplier.objects.filter(tenant=tenant).delete()
        created = updated = 0
        for row in rows:
            name = ImportService.normalize(row.get('name') or row.get('Name'))
            if not name:
                continue
            obj, was_created = Supplier.objects.update_or_create(
                tenant=tenant,
                name=name,
                defaults={
                    'service_description': ImportService.normalize(row.get('service_description') or row.get('Beschreibung') or row.get('Service')),
                    'criticality': (ImportService.normalize(row.get('criticality') or row.get('Kritikalität')) or 'MEDIUM').upper(),
                },
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated

    @staticmethod
    def import_assets(tenant, rows: Iterable[dict], replace_existing=False):
        if replace_existing:
            InformationAsset.objects.filter(tenant=tenant).delete()
        created = updated = 0
        type_map = {choice[0].lower(): choice[0] for choice in InformationAsset.Type.choices}
        crit_map = {choice[0].lower(): choice[0] for choice in InformationAsset.Criticality.choices}
        for row in rows:
            name = ImportService.normalize(row.get('name') or row.get('Name'))
            if not name:
                continue
            bu_name = ImportService.normalize(row.get('business_unit') or row.get('Geschäftsbereich'))
            business_unit = None
            if bu_name:
                business_unit, _ = BusinessUnit.objects.get_or_create(tenant=tenant, name=bu_name)
            obj, was_created = InformationAsset.objects.update_or_create(
                tenant=tenant,
                name=name,
                defaults={
                    'business_unit': business_unit,
                    'asset_type': type_map.get(ImportService.normalize(row.get('asset_type') or row.get('Typ')).lower(), InformationAsset.Type.APPLICATION),
                    'criticality': crit_map.get(ImportService.normalize(row.get('criticality') or row.get('Kritikalität')).lower(), InformationAsset.Criticality.MEDIUM),
                    'description': ImportService.normalize(row.get('description') or row.get('Beschreibung')),
                    'confidentiality': ImportService.normalize(row.get('confidentiality') or row.get('Vertraulichkeit')),
                    'integrity': ImportService.normalize(row.get('integrity') or row.get('Integrität')),
                    'availability': ImportService.normalize(row.get('availability') or row.get('Verfügbarkeit')),
                    'lifecycle_status': ImportService.normalize(row.get('lifecycle_status') or row.get('Lifecycle')),
                    'is_in_scope': not (ImportService.normalize(row.get('in_scope') or row.get('ImScope')).lower() in {'0', 'false', 'no', 'nein'}),
                },
            )
            created += int(was_created)
            updated += int(not was_created)
        return created, updated
