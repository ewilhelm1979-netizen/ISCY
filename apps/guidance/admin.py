from django.contrib import admin
from .models import GuidanceStep, TenantJourneyState


@admin.register(GuidanceStep)
class GuidanceStepAdmin(admin.ModelAdmin):
    list_display = ('sort_order', 'title', 'phase', 'code', 'route_name', 'is_required', 'is_active')
    list_filter = ('phase', 'is_required', 'is_active')
    search_fields = ('title', 'code', 'description')


@admin.register(TenantJourneyState)
class TenantJourneyStateAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'current_step', 'progress_percent', 'updated_at')
    search_fields = ('tenant__name',)
