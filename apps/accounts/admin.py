from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('ISMS', {'fields': ('role', 'tenant', 'job_title')}),
    )
    list_display = ('username', 'email', 'role', 'tenant', 'is_staff')
