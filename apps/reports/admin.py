from django.contrib import admin
from .models import ReportSnapshot


@admin.register(ReportSnapshot)
class ReportSnapshotAdmin(admin.ModelAdmin):
    list_display = ('title', 'tenant', 'iso_readiness_percent', 'created_at')
    search_fields = ('title', 'tenant__name')
