from django.conf import settings
from django.core.checks import Error, register


RUST_SERVICE_BACKEND_SETTINGS = (
    'LOCAL_LLM_BACKEND',
    'RISK_SCORING_BACKEND',
    'GUIDANCE_SCORING_BACKEND',
    'REPORT_SUMMARY_BACKEND',
    'REPORT_SNAPSHOT_BACKEND',
    'DASHBOARD_SUMMARY_BACKEND',
    'CATALOG_BACKEND',
    'REQUIREMENTS_BACKEND',
    'ASSET_INVENTORY_BACKEND',
    'PROCESS_REGISTER_BACKEND',
    'RISK_REGISTER_BACKEND',
    'EVIDENCE_REGISTER_BACKEND',
    'ASSESSMENT_REGISTER_BACKEND',
    'ROADMAP_REGISTER_BACKEND',
    'WIZARD_RESULTS_BACKEND',
    'IMPORT_CENTER_BACKEND',
    'PRODUCT_SECURITY_BACKEND',
)


@register()
def rust_only_cutover_checks(app_configs, **kwargs):
    if not getattr(settings, 'RUST_ONLY_MODE', False):
        return []

    errors = []
    if not getattr(settings, 'RUST_BACKEND_URL', '').strip():
        errors.append(Error(
            'RUST_ONLY_MODE ist aktiv, aber RUST_BACKEND_URL ist nicht gesetzt.',
            hint='Setze RUST_BACKEND_URL auf den laufenden Rust-Service, z. B. http://127.0.0.1:9000 oder http://rust-backend:9000.',
            id='iscy.E001',
        ))

    if not getattr(settings, 'RUST_STRICT_MODE', False):
        errors.append(Error(
            'RUST_ONLY_MODE ist aktiv, aber RUST_STRICT_MODE ist deaktiviert.',
            hint='Setze RUST_STRICT_MODE=True, damit Django nicht still auf Legacy-Python-Pfade zurueckfaellt.',
            id='iscy.E002',
        ))

    if not getattr(settings, 'VULN_INTEL_RUST_ONLY', False):
        errors.append(Error(
            'RUST_ONLY_MODE ist aktiv, aber VULN_INTEL_RUST_ONLY ist deaktiviert.',
            hint='Setze VULN_INTEL_RUST_ONLY=True, damit CVE-Importe und Normalisierung nicht ueber Python-Fallbacks laufen.',
            id='iscy.E003',
        ))

    legacy_backends = [
        name
        for name in RUST_SERVICE_BACKEND_SETTINGS
        if str(getattr(settings, name, '') or '').strip().lower() != 'rust_service'
    ]
    if legacy_backends:
        errors.append(Error(
            'RUST_ONLY_MODE ist aktiv, aber migrierte Backends sind nicht auf rust_service gesetzt.',
            hint='Setze diese Backends auf rust_service: ' + ', '.join(legacy_backends),
            id='iscy.E004',
        ))

    return errors
