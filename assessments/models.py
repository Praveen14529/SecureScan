from django.db import models
from django.urls import reverse
from django.utils import timezone


CRITICALITY_CHOICES = [
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

ASSET_TYPE_CHOICES = [
    ("server", "Server"),
    ("workstation", "Workstation"),
    ("network_device", "Network Device"),
    ("application", "Application / Software"),
    ("database", "Database"),
    ("cloud_service", "Cloud Service"),
    ("data_store", "Data Store"),
    ("other", "Other"),
]

# Criticality feeds into overall risk as a multiplier, so a checklist gap on
# a "critical" asset is weighted more heavily than the same gap on a "low"
# asset.
CRITICALITY_MULTIPLIER = {
    "low": 0.7,
    "medium": 1.0,
    "high": 1.3,
    "critical": 1.6,
}

ANSWER_CHOICES = [
    (0, "Non-compliant"),
    (1, "Partially compliant"),
    (2, "Largely compliant"),
    (3, "Fully compliant"),
]
ANSWER_MAX_VALUE = 3  # highest value in ANSWER_CHOICES

RISK_LEVELS = [
    ("low", "Low", 0, 25),
    ("medium", "Medium", 25, 50),
    ("high", "High", 50, 75),
    ("critical", "Critical", 75, 101),
]


def risk_level_for_score(score):
    """score is a 0-100 risk score (higher = riskier)."""
    for key, label, lower, upper in RISK_LEVELS:
        if lower <= score < upper:
            return key, label
    return "critical", "Critical"


class Asset(models.Model):
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=30, choices=ASSET_TYPE_CHOICES, default="other")
    owner = models.CharField(max_length=150, blank=True, help_text="Business/technical owner")
    criticality = models.CharField(max_length=10, choices=CRITICALITY_CHOICES, default="medium")
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("asset_detail", args=[self.pk])


class ChecklistCategory(models.Model):
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "name"]
        verbose_name_plural = "Checklist categories"

    def __str__(self):
        return self.name


class ChecklistQuestion(models.Model):
    category = models.ForeignKey(ChecklistCategory, on_delete=models.CASCADE, related_name="questions")
    text = models.CharField(max_length=500)
    guidance = models.TextField(blank=True, help_text="Notes on what to check / evidence to request")
    weight = models.PositiveIntegerField(default=1, help_text="Relative importance of this control (1-5)")
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["category__order", "order", "id"]

    def __str__(self):
        return f"[{self.category}] {self.text[:60]}"


class Assessment(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
    ]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="assessments")
    title = models.CharField(max_length=200)
    assessor = models.CharField(max_length=150, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} ({self.asset.name})"

    def get_absolute_url(self):
        return reverse("assessment_detail", args=[self.pk])

    # ---- Scoring logic ---------------------------------------------------
    def compliance_percentage(self):
        """Weighted average compliance across answered questions, 0-100."""
        responses = self.responses.select_related("question").all()
        total_weight = sum(r.question.weight for r in responses)
        if not total_weight:
            return None
        achieved = sum(r.question.weight * r.answer for r in responses)
        max_possible = total_weight * ANSWER_MAX_VALUE
        return round((achieved / max_possible) * 100, 1)

    def base_risk_score(self):
        """Inverse of compliance: how much risk exposure exists, 0-100."""
        pct = self.compliance_percentage()
        if pct is None:
            return None
        return round(100 - pct, 1)

    def risk_score(self):
        """Base risk score adjusted by asset criticality, capped at 100."""
        base = self.base_risk_score()
        if base is None:
            return None
        adjusted = base * CRITICALITY_MULTIPLIER.get(self.asset.criticality, 1.0)
        return round(min(adjusted, 100), 1)

    def risk_level(self):
        score = self.risk_score()
        if score is None:
            return None, "Not scored"
        return risk_level_for_score(score)

    def category_breakdown(self):
        """List of dicts with per-category compliance % for charting."""
        breakdown = []
        for category in ChecklistCategory.objects.all():
            responses = self.responses.filter(question__category=category).select_related("question")
            total_weight = sum(r.question.weight for r in responses)
            if not total_weight:
                continue
            achieved = sum(r.question.weight * r.answer for r in responses)
            pct = round((achieved / (total_weight * ANSWER_MAX_VALUE)) * 100, 1)
            breakdown.append({
                "category": category.name,
                "compliance_pct": pct,
                "risk_pct": round(100 - pct, 1),
            })
        return breakdown

    def mark_completed(self):
        self.status = "completed"
        self.completed_at = timezone.now()
        self.save()


class AssessmentResponse(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name="responses")
    question = models.ForeignKey(ChecklistQuestion, on_delete=models.CASCADE)
    answer = models.IntegerField(choices=ANSWER_CHOICES, default=0)
    evidence_notes = models.TextField(blank=True)

    class Meta:
        unique_together = ("assessment", "question")
        ordering = ["question__category__order", "question__order"]

    def __str__(self):
        return f"{self.assessment} - {self.question} -> {self.get_answer_display()}"
