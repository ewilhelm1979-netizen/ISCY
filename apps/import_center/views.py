from io import BytesIO
import csv

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import redirect
from django.views.generic import FormView, TemplateView, View
from openpyxl import Workbook

from apps.wizard.services import WizardService
from .forms import DataImportForm
from .services import ImportCenterBridge, ImportService, TEMPLATE_COLUMNS, COLUMN_SYNONYMS


class ImportCenterView(LoginRequiredMixin, FormView):
    template_name = 'imports/import_center.html'
    form_class = DataImportForm
    success_url = '/imports/preview/'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = WizardService.get_default_tenant(self.request.user)
        context['tenant'] = tenant
        context['examples'] = TEMPLATE_COLUMNS
        context['synonyms'] = COLUMN_SYNONYMS
        return context

    def form_valid(self, form):
        headers, rows = ImportService.read_rows(form.cleaned_data['file'])
        rows = rows[:200]
        preview_rows = [
            {str(k): '' if v is None else str(v) for k, v in row.items()}
            for row in rows
        ]
        import_type = form.cleaned_data['import_type']
        replace_existing = form.cleaned_data['replace_existing']
        selected_mapping = ImportService.default_mapping(import_type, headers)
        mapping_rows, extra_headers = ImportService.get_mapping_preview(import_type, headers, selected_mapping)
        matched = sum(1 for row in mapping_rows if row['status'] == 'ok')
        self.request.session['import_preview'] = {
            'import_type': import_type,
            'replace_existing': replace_existing,
            'headers': [str(h) for h in headers],
            'rows': preview_rows,
            'mapping_rows': mapping_rows,
            'selected_mapping': selected_mapping,
            'extra_headers': [str(h) for h in extra_headers],
            'matched': matched,
        }
        messages.info(self.request, f'Import-Vorschau erstellt: {matched}/{len(mapping_rows)} erwartete Spalten erkannt. Bitte prüfen, Zuordnung anpassen und bestätigen.')
        return super().form_valid(form)


class ImportPreviewView(LoginRequiredMixin, TemplateView):
    template_name = 'imports/preview.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        preview = self.request.session.get('import_preview')
        context['preview'] = preview
        context['sample_rows'] = (preview or {}).get('rows', [])[:10]
        context['headers'] = (preview or {}).get('headers', [])
        context['selected_mapping'] = (preview or {}).get('selected_mapping', {})
        return context

    def post(self, request, *args, **kwargs):
        tenant = WizardService.get_default_tenant(request.user)
        preview = request.session.get('import_preview')
        if not preview:
            messages.error(request, 'Keine Import-Vorschau vorhanden.')
            return redirect('imports:center')

        action = request.POST.get('action', 'confirm')
        import_type = preview.get('import_type')
        headers = preview.get('headers', [])
        expected_columns = ImportService.expected_columns(import_type)
        selected_mapping = {expected: request.POST.get(f'map_{expected}', '') for expected in expected_columns}
        mapping_rows, extra_headers = ImportService.get_mapping_preview(import_type, headers, selected_mapping)
        preview['selected_mapping'] = selected_mapping
        preview['mapping_rows'] = mapping_rows
        preview['extra_headers'] = extra_headers
        preview['matched'] = sum(1 for row in mapping_rows if row['status'] == 'ok')
        request.session['import_preview'] = preview

        if action == 'update':
            messages.info(request, 'Import-Zuordnung aktualisiert. Prüfen Sie nun die Feld-zu-Feld-Zuordnung und bestätigen Sie danach den Import.')
            return redirect('imports:preview')

        if not selected_mapping.get('name'):
            messages.error(request, 'Die Pflichtzuordnung für das Feld „name“ fehlt. Bitte ordnen Sie mindestens das Namensfeld zu.')
            return redirect('imports:preview')

        raw_rows = preview.get('rows', [])
        rows = ImportService.apply_mapping(raw_rows, selected_mapping)
        replace_existing = preview.get('replace_existing', False)
        rust_result = ImportCenterBridge.apply_import(
            request,
            tenant,
            import_type,
            rows,
            replace_existing=replace_existing,
        )
        if rust_result is not None:
            created, updated = rust_result.created, rust_result.updated
            skipped_note = f' {rust_result.skipped} Zeile(n) ohne Name uebersprungen.' if rust_result.skipped else ''
            messages.success(request, f'Import übernommen: {created} neu, {updated} aktualisiert.{skipped_note}')
        else:
            if import_type == DataImportForm.ImportType.BUSINESS_UNITS:
                created, updated = ImportService.import_business_units(tenant, rows, replace_existing=replace_existing)
            elif import_type == DataImportForm.ImportType.PROCESSES:
                created, updated = ImportService.import_processes(tenant, rows, replace_existing=replace_existing)
            elif import_type == DataImportForm.ImportType.SUPPLIERS:
                created, updated = ImportService.import_suppliers(tenant, rows, replace_existing=replace_existing)
            else:
                created, updated = ImportService.import_assets(tenant, rows, replace_existing=replace_existing)
            messages.success(request, f'Import übernommen: {created} neu, {updated} aktualisiert.')
        request.session.pop('import_preview', None)
        return redirect('imports:center')


class ImportGuideView(LoginRequiredMixin, TemplateView):
    template_name = 'imports/guide.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['examples'] = TEMPLATE_COLUMNS
        context['synonyms'] = COLUMN_SYNONYMS
        return context


class ImportMappingAssistantView(LoginRequiredMixin, TemplateView):
    template_name = 'imports/mapping_assistant.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        import_type = self.request.GET.get('type', 'processes')
        expected = TEMPLATE_COLUMNS.get(import_type, TEMPLATE_COLUMNS['processes'])
        context['selected_type'] = import_type
        context['expected_columns'] = expected
        context['all_types'] = TEMPLATE_COLUMNS
        context['mapping_rows'] = [
            {'expected': col, 'synonyms': COLUMN_SYNONYMS.get(col, []), 'required': col == 'name'}
            for col in expected
        ]
        return context


class ImportTemplateDownloadView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        import_type = kwargs['import_type']
        fmt = kwargs['fmt']
        columns = TEMPLATE_COLUMNS.get(import_type)
        if not columns:
            return HttpResponse(status=404)
        filename = f'import-template-{import_type}.{fmt}'
        if fmt == 'csv':
            response = HttpResponse(content_type='text/csv; charset=utf-8')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            writer = csv.writer(response)
            writer.writerow(columns)
            return response
        wb = Workbook()
        ws = wb.active
        ws.title = 'Template'
        ws.append(columns)
        sample = ['' for _ in columns]
        if 'name' in columns:
            sample[columns.index('name')] = 'Beispiel'
        if 'status' in columns:
            sample[columns.index('status')] = 'PARTIAL'
        if 'criticality' in columns:
            sample[columns.index('criticality')] = 'HIGH'
        if 'asset_type' in columns:
            sample[columns.index('asset_type')] = 'APPLICATION'
        ws.append(sample)
        output = BytesIO()
        wb.save(output)
        output.seek(0)
        response = HttpResponse(output.getvalue(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
