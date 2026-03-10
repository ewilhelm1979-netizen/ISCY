from django.contrib import admin
from .models import Risk, RiskCategory


@admin.register(RiskCategory)
class RiskCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'sort_order')
    list_filter = ('tenant',)


@admin.register(Risk)
class RiskAdmin(admin.ModelAdmin):
    list_display = ('title', 'tenant', 'impact', 'likelihood', 'score', 'risk_level', 'status', 'owner')
    list_filter = ('tenant', 'impact', 'likelihood', 'status', 'treatment_strategy')
    search_fields = ('title', 'description')
