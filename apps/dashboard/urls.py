from django.urls import path
from .views import DashboardView, DashboardPortfolioPdfView

app_name = 'dashboard'

urlpatterns = [
    path('', DashboardView.as_view(), name='home'),
    path('portfolio.pdf', DashboardPortfolioPdfView.as_view(), name='portfolio-pdf'),
]
