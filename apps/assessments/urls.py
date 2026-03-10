from django.urls import path
from .views import (
    ApplicabilityCreateView, ApplicabilityListView,
    AssessmentCreateView, AssessmentListView,
    MeasureCreateView, MeasureListView,
)
from .v20_views import (
    SoAListView, SoAGenerateView, SoADetailView, SoAEntryUpdateView,
    AuditListView, AuditCreateView, AuditDetailView, AuditUpdateView,
    FindingCreateView, FindingUpdateView,
    ReviewListView, ReviewCreateView, ReviewDetailView, ReviewUpdateView,
    ReviewActionCreateView,
)

app_name = 'assessments'

urlpatterns = [
    path('', AssessmentListView.as_view(), name='list'),
    path('new/', AssessmentCreateView.as_view(), name='create'),
    path('applicability/', ApplicabilityListView.as_view(), name='applicability_list'),
    path('applicability/new/', ApplicabilityCreateView.as_view(), name='applicability_create'),
    path('measures/', MeasureListView.as_view(), name='measure_list'),
    path('measures/new/', MeasureCreateView.as_view(), name='measure_create'),
    # V20: SoA
    path('soa/', SoAListView.as_view(), name='soa_list'),
    path('soa/generate/', SoAGenerateView.as_view(), name='soa_generate'),
    path('soa/<int:pk>/', SoADetailView.as_view(), name='soa_detail'),
    path('soa/entry/<int:pk>/edit/', SoAEntryUpdateView.as_view(), name='soa_entry_edit'),
    # V20: Audit
    path('audits/', AuditListView.as_view(), name='audit_list'),
    path('audits/new/', AuditCreateView.as_view(), name='audit_create'),
    path('audits/<int:pk>/', AuditDetailView.as_view(), name='audit_detail'),
    path('audits/<int:pk>/edit/', AuditUpdateView.as_view(), name='audit_edit'),
    path('audits/<int:audit_pk>/findings/new/', FindingCreateView.as_view(), name='finding_create'),
    path('findings/<int:pk>/edit/', FindingUpdateView.as_view(), name='finding_edit'),
    # V20: Management Review
    path('reviews/', ReviewListView.as_view(), name='review_list'),
    path('reviews/new/', ReviewCreateView.as_view(), name='review_create'),
    path('reviews/<int:pk>/', ReviewDetailView.as_view(), name='review_detail'),
    path('reviews/<int:pk>/edit/', ReviewUpdateView.as_view(), name='review_edit'),
    path('reviews/<int:review_pk>/actions/new/', ReviewActionCreateView.as_view(), name='review_action_create'),
]
