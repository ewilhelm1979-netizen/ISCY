from django.contrib import admin
from .models import Requirement

@admin.register(Requirement)
class RequirementAdmin(admin.ModelAdmin):
    list_display = ('framework', 'code', 'title', 'domain', 'is_active')
    list_filter = ('framework', 'domain', 'is_active')
    search_fields = ('code', 'title', 'description')
