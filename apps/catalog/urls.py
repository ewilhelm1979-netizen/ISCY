from django.urls import path
from .views import DomainListView

app_name = 'catalog'

urlpatterns = [
    path('', DomainListView.as_view(), name='domains'),
]
