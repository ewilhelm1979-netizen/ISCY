from django.urls import path
from .views import (
    WizardApplicabilityView,
    WizardMaturityView,
    WizardProfileView,
    WizardResultsView,
    WizardScopeView,
    WizardStartView,
)

app_name = 'wizard'

urlpatterns = [
    path('', WizardStartView.as_view(), name='start'),
    path('wizard/<int:pk>/profile/', WizardProfileView.as_view(), name='profile'),
    path('wizard/<int:pk>/applicability/', WizardApplicabilityView.as_view(), name='applicability'),
    path('wizard/<int:pk>/scope/', WizardScopeView.as_view(), name='scope'),
    path('wizard/<int:pk>/maturity/', WizardMaturityView.as_view(), name='maturity'),
    path('wizard/<int:pk>/results/', WizardResultsView.as_view(), name='results'),
]
