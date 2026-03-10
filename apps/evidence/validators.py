"""F15: Datei-Upload-Validierung fuer Evidenzen."""
import os
from django.conf import settings
from django.core.exceptions import ValidationError


def validate_evidence_file(file):
    """Validiert Dateityp und Groesse von Evidence-Uploads."""
    allowed_ext = getattr(settings, 'EVIDENCE_ALLOWED_EXTENSIONS',
                          ['.pdf', '.docx', '.xlsx', '.png', '.jpg', '.jpeg', '.csv', '.txt'])
    max_size_mb = getattr(settings, 'EVIDENCE_MAX_FILE_SIZE_MB', 25)
    max_size_bytes = max_size_mb * 1024 * 1024

    # Dateiendung pruefen
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in allowed_ext:
        raise ValidationError(
            f'Dateityp "{ext}" ist nicht erlaubt. Erlaubt: {", ".join(allowed_ext)}'
        )

    # Dateigroesse pruefen
    if file.size > max_size_bytes:
        raise ValidationError(
            f'Datei ist zu gross ({file.size / 1024 / 1024:.1f} MB). Maximum: {max_size_mb} MB.'
        )

    # Content-Type Basispruefung
    content_type = getattr(file, 'content_type', '')
    suspicious_types = ['application/x-executable', 'application/x-msdos-program', 'text/html']
    if content_type in suspicious_types:
        raise ValidationError(
            f'Dateityp "{content_type}" ist aus Sicherheitsgruenden nicht erlaubt.'
        )
