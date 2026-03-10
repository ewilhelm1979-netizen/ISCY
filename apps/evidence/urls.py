from django.urls import path
from .views import EvidenceCreateView, EvidenceListView, EvidenceNeedSyncView, EvidenceUpdateView

app_name = 'evidence'

urlpatterns = [
    path('', EvidenceListView.as_view(), name='list'),
    path('new/', EvidenceCreateView.as_view(), name='create'),
    path('session/<int:pk>/sync-needs/', EvidenceNeedSyncView.as_view(), name='sync-needs'),
    path('<int:pk>/edit/', EvidenceUpdateView.as_view(), name='edit'),
]
