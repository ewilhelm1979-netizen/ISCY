from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.contrib.auth import views as auth_views
from apps.core import views as core_views

urlpatterns = [
    path('health/live/', core_views.live_health, name='health_live'),
    path('health/ready/', core_views.ready_health, name='health_ready'),
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('', include('apps.wizard.urls')),
    path('navigator/', include('apps.guidance.urls')),
    path('dashboard/', include('apps.dashboard.urls')),
    path('catalog/', include('apps.catalog.urls')),
    path('reports/', include('apps.reports.urls')),
    path('roadmap/', include('apps.roadmap.urls')),
    path('evidence/', include('apps.evidence.urls')),
    path('assets/', include('apps.assets_app.urls')),
    path('imports/', include('apps.import_center.urls')),
    path('processes/', include('apps.processes.urls')),
    path('requirements/', include('apps.requirements_app.urls')),
    path('risks/', include('apps.risks.urls')),
    path('assessments/', include('apps.assessments.urls')),
    path('organizations/', include('apps.organizations.urls')),
    path('product-security/', include('apps.product_security.urls')),
    path('cves/', include('apps.vulnerability_intelligence.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
