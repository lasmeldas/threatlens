from django.contrib import admin

from .models import Alert, AuditEntry, Upload

admin.site.register(Upload)
admin.site.register(Alert)
admin.site.register(AuditEntry)
