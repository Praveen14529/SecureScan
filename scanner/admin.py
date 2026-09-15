from django.contrib import admin
from .models import ScanRun, Finding


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("id", "hostname", "os_summary", "status", "started_at")
    list_filter = ("status",)
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "scan", "category", "severity")
    list_filter = ("category", "severity")
