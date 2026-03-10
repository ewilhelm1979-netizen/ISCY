from django.contrib import admin
from .models import AssessmentDomain, AssessmentQuestion, AnswerOption, RecommendationRule


class AnswerOptionInline(admin.TabularInline):
    model = AnswerOption
    extra = 0


class RecommendationRuleInline(admin.TabularInline):
    model = RecommendationRule
    extra = 0


@admin.register(AssessmentDomain)
class AssessmentDomainAdmin(admin.ModelAdmin):
    list_display = ('sort_order', 'name', 'code', 'weight')
    search_fields = ('name', 'code')


@admin.register(AssessmentQuestion)
class AssessmentQuestionAdmin(admin.ModelAdmin):
    list_display = ('sort_order', 'code', 'question_kind', 'wizard_step', 'domain', 'applies_to_nis2')
    list_filter = ('question_kind', 'wizard_step', 'domain', 'applies_to_nis2')
    search_fields = ('code', 'text')
    inlines = [AnswerOptionInline, RecommendationRuleInline]
