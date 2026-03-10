from django.contrib import admin
from .models import (
    AISystem,
    Component,
    PSIRTCase,
    Product,
    ProductFamily,
    ProductRelease,
    ProductSecurityRoadmap,
    ProductSecurityRoadmapTask,
    ProductSecuritySnapshot,
    SecurityAdvisory,
    TARA,
    ThreatModel,
    ThreatScenario,
    Vulnerability,
)

for model in [
    ProductFamily,
    Product,
    ProductRelease,
    Component,
    AISystem,
    ThreatModel,
    ThreatScenario,
    TARA,
    Vulnerability,
    PSIRTCase,
    SecurityAdvisory,
    ProductSecurityRoadmap,
    ProductSecurityRoadmapTask,
    ProductSecuritySnapshot,
]:
    admin.site.register(model)
