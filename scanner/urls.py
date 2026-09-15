from django.urls import path
from . import views

urlpatterns = [
    path("", views.scan_dashboard, name="scan_dashboard"),
    path("run-demo/", views.scan_run_demo, name="scan_run_demo"),
    path("download/", views.download_agent, name="download_agent"),
    path("scan/<uuid:public_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:public_id>/export/pdf/", views.scan_export_pdf, name="scan_export_pdf"),
    path("scan/<uuid:public_id>/export/docx/", views.scan_export_docx, name="scan_export_docx"),
    path("api/scans/submit/", views.api_submit_scan, name="api_submit_scan"),
]
