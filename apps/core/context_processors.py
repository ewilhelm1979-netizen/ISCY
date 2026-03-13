from django.conf import settings


def app_metadata(request):
    return {
        'APP_DISPLAY_NAME': getattr(settings, 'APP_DISPLAY_NAME', 'ISCY'),
    }
