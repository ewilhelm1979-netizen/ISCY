from django.urls import path
from .views import ImportCenterView, ImportGuideView, ImportMappingAssistantView, ImportPreviewView, ImportTemplateDownloadView

app_name = 'imports'

urlpatterns = [
    path('', ImportCenterView.as_view(), name='center'),
    path('preview/', ImportPreviewView.as_view(), name='preview'),
    path('guide/', ImportGuideView.as_view(), name='guide'),
    path('mapping/', ImportMappingAssistantView.as_view(), name='mapping'),
    path('templates/<str:import_type>.<str:fmt>/', ImportTemplateDownloadView.as_view(), name='template-download'),
]
