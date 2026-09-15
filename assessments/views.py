from django.contrib import messages
from django.db import models as dj_models
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404

from .models import (
    Asset, ChecklistCategory, ChecklistQuestion, Assessment, AssessmentResponse,
    ANSWER_CHOICES, CRITICALITY_CHOICES, ASSET_TYPE_CHOICES,
)
from .forms import AssetForm, AssessmentCreateForm
from .reports import render_assessment_pdf, render_assessment_docx


def dashboard(request):
    assessments = Assessment.objects.select_related("asset").all()

    status = request.GET.get("status")
    criticality = request.GET.get("criticality")
    if status:
        assessments = assessments.filter(status=status)
    if criticality:
        assessments = assessments.filter(asset__criticality=criticality)

    rows = []
    level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in assessments:
        score = a.risk_score()
        level_key, level_label = a.risk_level()
        if level_key:
            level_counts[level_key] += 1
        rows.append({
            "assessment": a,
            "score": score,
            "level_key": level_key,
            "level_label": level_label,
        })

    context = {
        "rows": rows,
        "total_assets": Asset.objects.count(),
        "total_assessments": Assessment.objects.count(),
        "level_counts": level_counts,
        "status_choices": Assessment.STATUS_CHOICES,
        "criticality_choices": CRITICALITY_CHOICES,
        "selected_status": status or "",
        "selected_criticality": criticality or "",
    }
    return render(request, "assessments/dashboard.html", context)


def asset_list(request):
    assets = Asset.objects.annotate(assessment_count=dj_models.Count("assessments"))
    return render(request, "assessments/asset_list.html", {"assets": assets})


def asset_create(request):
    if request.method == "POST":
        form = AssetForm(request.POST)
        if form.is_valid():
            asset = form.save()
            messages.success(request, f'Asset "{asset.name}" created.')
            return redirect("asset_detail", pk=asset.pk)
    else:
        form = AssetForm()
    return render(request, "assessments/asset_form.html", {"form": form})


def asset_detail(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    assessments = asset.assessments.all()
    rows = [{"assessment": a, "score": a.risk_score(), "level": a.risk_level()[1]} for a in assessments]
    return render(request, "assessments/asset_detail.html", {"asset": asset, "rows": rows})


def assessment_create(request, asset_pk):
    asset = get_object_or_404(Asset, pk=asset_pk)
    if request.method == "POST":
        form = AssessmentCreateForm(request.POST)
        if form.is_valid():
            assessment = form.save(commit=False)
            assessment.asset = asset
            assessment.status = "in_progress"
            assessment.save()
            return redirect("assessment_fill", pk=assessment.pk)
    else:
        form = AssessmentCreateForm(initial={"title": f"Risk Assessment - {asset.name}"})
    return render(request, "assessments/assessment_create.html", {"form": form, "asset": asset})


def assessment_fill(request, pk):
    assessment = get_object_or_404(Assessment, pk=pk)
    categories = ChecklistCategory.objects.prefetch_related("questions").all()
    existing = {r.question_id: r for r in assessment.responses.all()}

    if request.method == "POST":
        for category in categories:
            for question in category.questions.filter(is_active=True):
                field = f"q_{question.id}"
                notes_field = f"notes_{question.id}"
                if field in request.POST:
                    answer_val = int(request.POST[field])
                    notes_val = request.POST.get(notes_field, "")
                    AssessmentResponse.objects.update_or_create(
                        assessment=assessment,
                        question=question,
                        defaults={"answer": answer_val, "evidence_notes": notes_val},
                    )
        if request.POST.get("mark_completed"):
            assessment.mark_completed()
            messages.success(request, "Assessment marked as completed.")
            return redirect("assessment_detail", pk=assessment.pk)
        else:
            assessment.save()  # bump updated_at
            messages.success(request, "Progress saved.")
            return redirect("assessment_fill", pk=assessment.pk)

    return render(request, "assessments/assessment_fill.html", {
        "assessment": assessment,
        "categories": categories,
        "existing": existing,
        "answer_choices": ANSWER_CHOICES,
    })


def assessment_detail(request, pk):
    assessment = get_object_or_404(Assessment, pk=pk)
    breakdown = assessment.category_breakdown()
    level_key, level_label = assessment.risk_level()
    return render(request, "assessments/assessment_detail.html", {
        "assessment": assessment,
        "breakdown": breakdown,
        "score": assessment.risk_score(),
        "compliance": assessment.compliance_percentage(),
        "level_key": level_key,
        "level_label": level_label,
    })


def assessment_export_pdf(request, pk):
    assessment = get_object_or_404(Assessment, pk=pk)
    buffer = render_assessment_pdf(assessment)
    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="risk-assessment-{assessment.pk}.pdf"'
    return response


def assessment_export_docx(request, pk):
    assessment = get_object_or_404(Assessment, pk=pk)
    buffer = render_assessment_docx(assessment)
    response = HttpResponse(
        buffer,
        content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    response["Content-Disposition"] = f'attachment; filename="risk-assessment-{assessment.pk}.docx"'
    return response
