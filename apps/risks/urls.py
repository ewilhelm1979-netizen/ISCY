from django.urls import path
from .views import RiskCreateView, RiskDetailView, RiskListView, RiskUpdateView

app_name = 'risks'

urlpatterns = [
    path('', RiskListView.as_view(), name='list'),
    path('new/', RiskCreateView.as_view(), name='create'),
    path('<int:pk>/', RiskDetailView.as_view(), name='detail'),
    path('<int:pk>/edit/', RiskUpdateView.as_view(), name='edit'),
]
