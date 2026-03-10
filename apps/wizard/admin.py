from django.contrib import admin
from .models import AssessmentSession, SessionAnswer, DomainScore, GeneratedGap, GeneratedMeasure


@admin.register(AssessmentSession)
class AssessmentSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'tenant', 'assessment_type', 'status', 'current_step', 'progress_percent', 'updated_at')
    list_filter = ('assessment_type', 'status', 'current_step')


@admin.register(SessionAnswer)
class SessionAnswerAdmin(admin.ModelAdmin):
    list_display = ('session', 'question', 'score', 'selected_option')
    list_filter = ('question__question_kind',)


@admin.register(DomainScore)
class DomainScoreAdmin(admin.ModelAdmin):
    list_display = ('session', 'domain', 'score_percent', 'maturity_level', 'gap_level')


@admin.register(GeneratedGap)
class GeneratedGapAdmin(admin.ModelAdmin):
    list_display = ('session', 'domain', 'severity', 'title')
    list_filter = ('severity', 'domain')


@admin.register(GeneratedMeasure)
class GeneratedMeasureAdmin(admin.ModelAdmin):
    list_display = ('session', 'domain', 'priority', 'title', 'target_phase', 'status')
    list_filter = ('priority', 'measure_type', 'status')
