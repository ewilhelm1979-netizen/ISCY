from django.urls import path
from .views import ReportDetailView, ReportListView, ReportPdfView, ReportProPdfView

app_name = 'reports'

urlpatterns = [
    path('', ReportListView.as_view(), name='list'),
    path('<int:pk>/', ReportDetailView.as_view(), name='detail'),
    path('<int:pk>/pdf/', ReportPdfView.as_view(), name='pdf'),
    path('<int:pk>/pdf-pro/', ReportProPdfView.as_view(), name='pdf_pro'),
]
