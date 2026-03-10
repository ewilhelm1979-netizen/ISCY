from django.urls import path
from .views import ProcessCreateView, ProcessDetailView, ProcessListView

app_name = 'processes'

urlpatterns = [
    path('', ProcessListView.as_view(), name='list'),
    path('new/', ProcessCreateView.as_view(), name='create'),
    path('<int:pk>/', ProcessDetailView.as_view(), name='detail'),
]
