from django.contrib import admin
from .models import Asset, ChecklistCategory, ChecklistQuestion, Assessment, AssessmentResponse


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "criticality", "owner", "created_at")
    list_filter = ("asset_type", "criticality")
    search_fields = ("name", "owner")


class ChecklistQuestionInline(admin.TabularInline):
    model = ChecklistQuestion
    extra = 1


@admin.register(ChecklistCategory)
class ChecklistCategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "order")
    inlines = [ChecklistQuestionInline]


@admin.register(ChecklistQuestion)
class ChecklistQuestionAdmin(admin.ModelAdmin):
    list_display = ("text", "category", "weight", "is_active")
    list_filter = ("category", "is_active")
    search_fields = ("text",)


class AssessmentResponseInline(admin.TabularInline):
    model = AssessmentResponse
    extra = 0


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ("title", "asset", "status", "assessor", "created_at")
    list_filter = ("status", "asset__criticality")
    inlines = [AssessmentResponseInline]
