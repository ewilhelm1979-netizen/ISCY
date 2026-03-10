from django.urls import path
from .views import GuidanceDashboardView, GuidanceStepDetailView

app_name = 'guidance'

urlpatterns = [
    path('', GuidanceDashboardView.as_view(), name='dashboard'),
    path('steps/<int:pk>/', GuidanceStepDetailView.as_view(), name='step-detail'),
]
