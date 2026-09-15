from django.db import models
from django.urls import reverse
import uuid

SEVERITY_CHOICES = [
    ("info", "Info"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

# Points each severity contributes toward the overall 0-100 risk score.
SEVERITY_POINTS = {
    "info": 0,
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}

CATEGORY_CHOICES = [
    ("system", "System Configuration"),
    ("network", "Network / Open Ports"),
    ("software", "Installed Software"),
]


class ScanRun(models.Model):
    STATUS_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    hostname = models.CharField(max_length=255, blank=True)
    os_summary = models.CharField(max_length=255, blank=True)
    deep_cve_lookup = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="running")
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    submitted_via_api = models.BooleanField(default=False)
    client_label = models.CharField(max_length=150, blank=True, help_text="Optional label the submitter gave this scan")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Scan #{self.pk} - {self.hostname} ({self.started_at:%Y-%m-%d %H:%M})"

    def get_absolute_url(self):
        return reverse("scan_detail", args=[self.public_id])

    def risk_score(self):
        findings = list(self.findings.all())
        if not findings:
            return 0
        points = sum(SEVERITY_POINTS.get(f.severity, 0) for f in findings)
        return min(100, points)

    def risk_level(self):
        score = self.risk_score()
        if score >= 70:
            return "critical", "Critical"
        if score >= 45:
            return "high", "High"
        if score >= 20:
            return "medium", "Medium"
        if score > 0:
            return "low", "Low"
        return "low", "Low"

    def severity_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings.all():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def category_breakdown(self):
        breakdown = []
        for key, label in CATEGORY_CHOICES:
            cat_findings = [f for f in self.findings.all() if f.category == key]
            if not cat_findings:
                continue
            points = sum(SEVERITY_POINTS.get(f.severity, 0) for f in cat_findings)
            breakdown.append({
                "category": label,
                "count": len(cat_findings),
                "risk_points": min(100, points),
            })
        return breakdown


class Finding(models.Model):
    scan = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="info")
    description = models.TextField(blank=True)
    evidence = models.TextField(blank=True, help_text="Raw detail supporting this finding")
    mitigation = models.TextField(blank=True)

    class Meta:
        ordering = ["-severity", "category", "title"]

    def __str__(self):
        return f"[{self.severity}] {self.title}"

    def severity_rank(self):
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return order.get(self.severity, 0)
