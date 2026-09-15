import json
import os
import time

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse, FileResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import ScanRun, Finding
from . import engine
from .reports import render_scan_pdf, render_scan_docx

SESSION_KEY = "my_scan_ids"
MAX_FINDINGS_PER_SCAN = 500
MAX_FIELD_LEN = 2000
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_SUBMISSIONS = 5


def _track_scan(request, public_id):
    ids = request.session.get(SESSION_KEY, [])
    public_id = str(public_id)
    if public_id in ids:
        ids.remove(public_id)
    ids.insert(0, public_id)
    request.session[SESSION_KEY] = ids[:50]


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def scan_dashboard(request):
    ids = request.session.get(SESSION_KEY, [])
    scans = list(ScanRun.objects.filter(public_id__in=ids))
    scans.sort(key=lambda s: ids.index(str(s.public_id)))

    rows = []
    for s in scans:
        level_key, level_label = s.risk_level()
        rows.append({"scan": s, "score": s.risk_score(), "level_key": level_key, "level_label": level_label})

    return render(request, "scanner/dashboard.html", {"rows": rows})


def scan_run_demo(request):
    """Runs the scan against the server itself, clearly as a demo — this is
    NOT a scan of the visitor's own machine (a browser can't do that)."""
    if request.method != "POST":
        return redirect("scan_dashboard")

    scan = ScanRun.objects.create(status="running", client_label="Live demo (scans the server)")
    try:
        hostname, os_summary, findings = engine.run_full_scan(deep_cve_lookup=False)
        scan.hostname = hostname
        scan.os_summary = os_summary
        for f in findings:
            Finding.objects.create(scan=scan, **f)
        scan.status = "completed"
        scan.finished_at = timezone.now()
        scan.save()
        messages.success(request, f"Demo scan completed — {len(findings)} findings. "
                                   "Note: this scanned the server, not your own PC.")
    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        scan.finished_at = timezone.now()
        scan.save()
        messages.error(request, f"Scan failed: {e}")

    _track_scan(request, scan.public_id)
    return redirect("scan_detail", public_id=scan.public_id)


def scan_detail(request, public_id):
    scan = get_object_or_404(ScanRun, public_id=public_id)
    _track_scan(request, scan.public_id)
    findings = scan.findings.all()

    category = request.GET.get("category")
    severity = request.GET.get("severity")
    if category:
        findings = findings.filter(category=category)
    if severity:
        findings = findings.filter(severity=severity)

    level_key, level_label = scan.risk_level()
    return render(request, "scanner/scan_detail.html", {
        "scan": scan,
        "findings": findings,
        "score": scan.risk_score(),
        "level_key": level_key,
        "level_label": level_label,
        "severity_counts": scan.severity_counts(),
        "breakdown": scan.category_breakdown(),
        "selected_category": category or "",
        "selected_severity": severity or "",
    })


def scan_export_pdf(request, public_id):
    scan = get_object_or_404(ScanRun, public_id=public_id)
    buffer = render_scan_pdf(scan)
    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="vulnerability-scan-{scan.public_id}.pdf"'
    return response


def scan_export_docx(request, public_id):
    scan = get_object_or_404(ScanRun, public_id=public_id)
    buffer = render_scan_docx(scan)
    response = HttpResponse(
        buffer,
        content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    response["Content-Disposition"] = f'attachment; filename="vulnerability-scan-{scan.public_id}.docx"'
    return response


def download_agent(request):
    agent_path = os.path.join(os.path.dirname(__file__), "agent", "scan_agent.py")
    with open(agent_path, "r") as fh:
        content = fh.read()

    server_url = request.build_absolute_uri("/").rstrip("/")
    content = content.replace("__SERVER_URL__", server_url)

    response = HttpResponse(content, content_type="text/x-python")
    response["Content-Disposition"] = 'attachment; filename="scan_agent.py"'
    return response


def _rate_limited(request):
    key = f"scan_submit_rl_{_client_ip(request)}"
    count = cache.get(key, 0)
    if count >= RATE_LIMIT_MAX_SUBMISSIONS:
        return True
    cache.set(key, count + 1, RATE_LIMIT_WINDOW_SECONDS)
    return False


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CATEGORIES = {"system", "network", "software"}


@csrf_exempt
@require_POST
def api_submit_scan(request):
    """Public endpoint the downloadable agent posts results to. No auth —
    this is meant to be usable by anyone who downloads the agent — so
    everything here is defensively validated and size/rate limited."""
    if _rate_limited(request):
        return JsonResponse({"error": "Too many submissions from this IP — please wait a minute."}, status=429)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    findings_in = data.get("findings")
    if not isinstance(findings_in, list):
        return JsonResponse({"error": "'findings' must be a list."}, status=400)
    if len(findings_in) > MAX_FINDINGS_PER_SCAN:
        return JsonResponse({"error": f"Too many findings (max {MAX_FINDINGS_PER_SCAN})."}, status=400)

    def _clean(value, max_len=MAX_FIELD_LEN):
        return str(value)[:max_len] if value is not None else ""

    cleaned_findings = []
    for f in findings_in:
        if not isinstance(f, dict):
            continue
        category = f.get("category")
        severity = f.get("severity")
        title = f.get("title")
        if category not in VALID_CATEGORIES or severity not in VALID_SEVERITIES or not title:
            continue
        cleaned_findings.append({
            "category": category,
            "severity": severity,
            "title": _clean(title, 300),
            "description": _clean(f.get("description"), MAX_FIELD_LEN),
            "evidence": _clean(f.get("evidence"), MAX_FIELD_LEN),
            "mitigation": _clean(f.get("mitigation"), MAX_FIELD_LEN),
        })

    if not cleaned_findings:
        return JsonResponse({"error": "No valid findings in submission."}, status=400)

    scan = ScanRun.objects.create(
        hostname=_clean(data.get("hostname"), 255),
        os_summary=_clean(data.get("os_summary"), 255),
        deep_cve_lookup=bool(data.get("deep_cve_lookup")),
        client_label=_clean(data.get("client_label"), 150),
        submitted_via_api=True,
        status="completed",
        finished_at=timezone.now(),
    )
    Finding.objects.bulk_create([Finding(scan=scan, **f) for f in cleaned_findings])

    report_url = request.build_absolute_uri(scan.get_absolute_url())
    return JsonResponse({
        "scan_id": str(scan.public_id),
        "report_url": report_url,
        "risk_score": scan.risk_score(),
        "risk_level": scan.risk_level()[1],
        "findings_saved": len(cleaned_findings),
    }, status=201)
