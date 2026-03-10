from django.contrib import admin
from .models import RoadmapPlan, RoadmapPhase, RoadmapTask, RoadmapTaskDependency

admin.site.register(RoadmapPlan)
admin.site.register(RoadmapPhase)
admin.site.register(RoadmapTask)
admin.site.register(RoadmapTaskDependency)
