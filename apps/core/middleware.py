"""F09: Tenant-Isolation-Middleware.

Setzt request.tenant aus dem eingeloggten User. Alle Views und QuerySets
koennen sich darauf verlassen, dass request.tenant den aktuellen Mandanten
enthaelt (oder None fuer nicht-authentifizierte Requests).
"""

from django.utils.deprecation import MiddlewareMixin


class TenantMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.tenant = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            request.tenant = getattr(request.user, 'tenant', None)
