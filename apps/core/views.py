from django.db import connections
from django.http import JsonResponse


def live_health(request):
    return JsonResponse({'status': 'ok', 'service': 'isms-planner', 'check': 'live'})


def ready_health(request):
    db_ok = False
    db_error = ''
    try:
        connections['default'].cursor()
        db_ok = True
    except Exception as exc:  # pragma: no cover
        db_error = str(exc)
    status_code = 200 if db_ok else 503
    payload = {
        'status': 'ok' if db_ok else 'degraded',
        'service': 'isms-planner',
        'check': 'ready',
        'database': 'ok' if db_ok else 'error',
    }
    if db_error:
        payload['database_error'] = db_error
    return JsonResponse(payload, status=status_code)
