from django.urls import path
from .views import TenantCreateView, TenantListView
from .views_api import SectorContextApiView

app_name = 'organizations'

urlpatterns = [
    path('', TenantListView.as_view(), name='list'),
    path('new/', TenantCreateView.as_view(), name='create'),
    path('api/sector-context/', SectorContextApiView.as_view(), name='sector_context_api'),
]
