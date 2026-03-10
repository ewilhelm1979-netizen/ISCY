from django.urls import path
from .views import RoadmapKanbanView, RoadmapPdfView, RoadmapPngView, RoadmapPlanDetailView, RoadmapPlanListView, RoadmapTaskUpdateView

app_name = 'roadmap'

urlpatterns = [
    path('', RoadmapPlanListView.as_view(), name='list'),
    path('<int:pk>/', RoadmapPlanDetailView.as_view(), name='detail'),
    path('<int:pk>/kanban/', RoadmapKanbanView.as_view(), name='kanban'),
    path('<int:pk>/pdf/', RoadmapPdfView.as_view(), name='pdf'),
    path('<int:pk>/png/', RoadmapPngView.as_view(), name='png'),
    path('tasks/<int:pk>/edit/', RoadmapTaskUpdateView.as_view(), name='task-edit'),
]
