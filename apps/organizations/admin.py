from django.contrib import admin
from .models import Tenant, LegalEntity, BusinessUnit, Site, Supplier

admin.site.register(Tenant)
admin.site.register(LegalEntity)
admin.site.register(BusinessUnit)
admin.site.register(Site)
admin.site.register(Supplier)
