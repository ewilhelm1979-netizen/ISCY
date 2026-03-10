from django.urls import path
from .views import RequirementListView

app_name = 'requirements'

urlpatterns = [
    path('', RequirementListView.as_view(), name='list'),
]
