from django.contrib import admin
from .models import Process

@admin.register(Process)
class ProcessAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'status', 'owner', 'documented', 'implemented', 'effective')
    list_filter = ('tenant', 'status', 'documented', 'implemented', 'effective')
    search_fields = ('name', 'description', 'scope')
