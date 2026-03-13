from django.contrib import admin
from .models import MappingVersion, RegulatorySource, Requirement, RequirementQuestionMapping


@admin.register(MappingVersion)
class MappingVersionAdmin(admin.ModelAdmin):
    list_display = ('framework', 'version', 'status', 'program_name', 'effective_on')
    list_filter = ('framework', 'status')
    search_fields = ('framework', 'version', 'title', 'program_name')


@admin.register(RegulatorySource)
class RegulatorySourceAdmin(admin.ModelAdmin):
    list_display = ('framework', 'code', 'authority', 'source_type', 'mapping_version')
    list_filter = ('framework', 'source_type', 'authority')
    search_fields = ('code', 'title', 'citation', 'url')


@admin.register(Requirement)
class RequirementAdmin(admin.ModelAdmin):
    list_display = ('framework', 'code', 'title', 'domain', 'mapping_version', 'is_active')
    list_filter = ('framework', 'domain', 'is_active', 'coverage_level')
    search_fields = ('code', 'title', 'description', 'legal_reference')


@admin.register(RequirementQuestionMapping)
class RequirementQuestionMappingAdmin(admin.ModelAdmin):
    list_display = ('requirement', 'question', 'mapping_version', 'strength')
    list_filter = ('requirement__framework', 'strength')
    search_fields = ('requirement__code', 'question__code', 'rationale')
