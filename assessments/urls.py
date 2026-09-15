from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("assets/", views.asset_list, name="asset_list"),
    path("assets/new/", views.asset_create, name="asset_create"),
    path("assets/<int:pk>/", views.asset_detail, name="asset_detail"),
    path("assets/<int:asset_pk>/assess/", views.assessment_create, name="assessment_create"),
    path("assessments/<int:pk>/fill/", views.assessment_fill, name="assessment_fill"),
    path("assessments/<int:pk>/", views.assessment_detail, name="assessment_detail"),
    path("assessments/<int:pk>/export/pdf/", views.assessment_export_pdf, name="assessment_export_pdf"),
    path("assessments/<int:pk>/export/docx/", views.assessment_export_docx, name="assessment_export_docx"),
]
