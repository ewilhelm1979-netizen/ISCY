from django.contrib import admin
from .models import EvidenceItem, RequirementEvidenceNeed


@admin.register(EvidenceItem)
class EvidenceItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'tenant', 'session', 'domain', 'measure', 'status', 'updated_at')
    list_filter = ('status', 'domain', 'tenant')
    search_fields = ('title', 'description', 'linked_requirement')


@admin.register(RequirementEvidenceNeed)
class RequirementEvidenceNeedAdmin(admin.ModelAdmin):
    list_display = ('title', 'tenant', 'session', 'requirement', 'status', 'covered_count', 'is_mandatory')
    list_filter = ('status', 'is_mandatory', 'tenant')
    search_fields = ('title', 'requirement__code', 'requirement__title')
