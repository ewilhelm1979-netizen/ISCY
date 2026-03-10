
from django.contrib import admin
from .models import InformationAsset


@admin.register(InformationAsset)
class InformationAssetAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'asset_type', 'criticality', 'is_in_scope')
    list_filter = ('asset_type', 'criticality', 'is_in_scope')
    search_fields = ('name', 'description')
