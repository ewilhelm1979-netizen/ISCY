from pathlib import Path
import os
from dotenv import load_dotenv
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

# --- F13: Kein unsicherer Default-Key. In Production MUSS SECRET_KEY gesetzt sein. ---
_secret = os.getenv('SECRET_KEY', '')
DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
if not _secret and not DEBUG:
    raise RuntimeError(
        'SECRET_KEY environment variable is not set. '
        'Refusing to start in non-DEBUG mode with an empty secret.'
    )
SECRET_KEY = _secret or 'dev-only-insecure-key-do-not-use-in-production'

ALLOWED_HOSTS = [host.strip() for host in os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') if host.strip()]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'apps.core',
    'apps.accounts',
    'apps.organizations',
    'apps.requirements_app',
    'apps.processes',
    'apps.risks',
    'apps.assessments',
    'apps.dashboard',
    'apps.guidance',
    'apps.catalog',
    'apps.wizard',
    'apps.roadmap',
    'apps.reports',
    'apps.evidence',
    'apps.assets_app',
    'apps.import_center',
    'apps.product_security',
    'apps.vulnerability_intelligence',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # F09: Tenant-Isolation-Middleware
    'apps.core.middleware.TenantMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

DATABASES = {
    'default': dj_database_url.parse(
        os.getenv('DATABASE_URL', f'sqlite:///{BASE_DIR / "db.sqlite3"}'),
        conn_max_age=600,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
]

LANGUAGE_CODE = 'de-de'
TIME_ZONE = 'Europe/Berlin'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'accounts.User'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = 'wizard:start'
LOGOUT_REDIRECT_URL = 'login'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# --- F15: Datei-Upload-Beschraenkungen ---
EVIDENCE_ALLOWED_EXTENSIONS = ['.pdf', '.docx', '.xlsx', '.png', '.jpg', '.jpeg', '.csv', '.txt', '.msg']
EVIDENCE_MAX_FILE_SIZE_MB = 25
DATA_UPLOAD_MAX_MEMORY_SIZE = EVIDENCE_MAX_FILE_SIZE_MB * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = EVIDENCE_MAX_FILE_SIZE_MB * 1024 * 1024

# --- F12: Konfigurierbare Evidence-Coverage-Schwellen ---
EVIDENCE_COVERAGE_THRESHOLDS = {
    'covered': 2,
    'partial': 1,
}

def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() == 'true'


# Reverse-Proxy / Production-Haertung
USE_X_FORWARDED_HOST = _env_bool('USE_X_FORWARDED_HOST', not DEBUG)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https') if _env_bool('TRUST_X_FORWARDED_PROTO', not DEBUG) else None
CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if origin.strip()]

if not DEBUG:
    SECURE_SSL_REDIRECT = _env_bool('SECURE_SSL_REDIRECT', False)
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    CSRF_COOKIE_SECURE = _env_bool('CSRF_COOKIE_SECURE', False)
    SECURE_HSTS_SECONDS = int(os.getenv('SECURE_HSTS_SECONDS', '0'))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', False)
    SECURE_HSTS_PRELOAD = _env_bool('SECURE_HSTS_PRELOAD', False)
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'

# Lokales LLM / CVE-Intelligence
LOCAL_LLM_ENABLED = os.getenv('LOCAL_LLM_ENABLED', 'False').lower() == 'true'
LOCAL_LLM_BACKEND = os.getenv('LOCAL_LLM_BACKEND', 'llama_cpp')
LOCAL_LLM_MODEL_NAME = os.getenv('LOCAL_LLM_MODEL_NAME', 'Qwen3-8B-GGUF')
LOCAL_LLM_MODEL_PATH = os.getenv('LOCAL_LLM_MODEL_PATH', '')
LOCAL_LLM_N_CTX = int(os.getenv('LOCAL_LLM_N_CTX', '8192'))
LOCAL_LLM_N_THREADS = int(os.getenv('LOCAL_LLM_N_THREADS', str(max(2, os.cpu_count() or 4))))
LOCAL_LLM_GPU_LAYERS = int(os.getenv('LOCAL_LLM_GPU_LAYERS', '0'))
LOCAL_LLM_VERBOSE_NATIVE = os.getenv('LOCAL_LLM_VERBOSE_NATIVE', 'False').lower() == 'true'
LOCAL_LLM_TEST_MAX_TOKENS = int(os.getenv('LOCAL_LLM_TEST_MAX_TOKENS', '96'))
NVD_API_KEY = os.getenv('NVD_API_KEY', '')
