from django.core.management.base import BaseCommand
from assessments.models import ChecklistCategory, ChecklistQuestion

CHECKLIST = [
    {
        "name": "Access Control",
        "description": "Authentication, authorization and account management controls.",
        "questions": [
            ("Multi-factor authentication is enforced for privileged/admin accounts.", 5,
             "Check IdP / AD policy, sample a few admin accounts."),
            ("Unique user accounts are used; shared/generic logins are avoided.", 3,
             "Review account list for generic names (admin, test, etc.)."),
            ("User access is reviewed periodically and revoked on offboarding.", 4,
             "Ask for last access review date and an offboarding ticket sample."),
            ("Least-privilege / role-based access control is applied.", 4,
             "Compare a sample user's access against their job role."),
        ],
    },
    {
        "name": "Network Security",
        "description": "Perimeter, segmentation and network monitoring controls.",
        "questions": [
            ("Firewall rules are documented and reviewed regularly.", 3,
             "Request the current firewall rule review log."),
            ("Network is segmented (e.g. VLANs) to separate critical assets.", 4,
             "Check network diagram for segmentation of sensitive zones."),
            ("Intrusion detection/prevention (IDS/IPS) is deployed and monitored.", 3,
             "Confirm IDS/IPS coverage and alerting."),
            ("Remote access uses VPN with strong authentication.", 4,
             "Verify VPN configuration and authentication method."),
        ],
    },
    {
        "name": "Data Protection",
        "description": "Encryption, backup and data handling practices.",
        "questions": [
            ("Sensitive data is encrypted at rest.", 5, "Check disk/DB encryption configuration."),
            ("Sensitive data is encrypted in transit (TLS).", 5, "Check TLS config / certificate validity."),
            ("Regular backups are taken and periodically restore-tested.", 4,
             "Ask for backup schedule and last successful restore test."),
            ("Data retention and disposal policy is defined and followed.", 2,
             "Review data classification/retention policy."),
        ],
    },
    {
        "name": "Vulnerability & Patch Management",
        "description": "Identifying and remediating known weaknesses.",
        "questions": [
            ("Critical/high vulnerabilities are patched within a defined SLA.", 5,
             "Sample recent vulnerability scan and patch timestamps."),
            ("Regular vulnerability scanning is performed on this asset.", 3,
             "Ask for the latest scan report."),
            ("Software and OS are running supported, up-to-date versions.", 3,
             "Check OS/software version against end-of-life dates."),
        ],
    },
    {
        "name": "Incident Response",
        "description": "Preparedness to detect, respond to and recover from incidents.",
        "questions": [
            ("A documented incident response plan exists and covers this asset.", 3,
             "Request the IR plan document."),
            ("Logging is enabled and centrally collected for this asset.", 4,
             "Check SIEM/log collection coverage."),
            ("Incident response roles and contacts are defined and current.", 2,
             "Review IR contact list / RACI."),
        ],
    },
    {
        "name": "Physical Security",
        "description": "Controls protecting physical access to the asset (where applicable).",
        "questions": [
            ("Physical access to the asset/hosting location is restricted and logged.", 3,
             "Check access logs / badge system for the hosting facility."),
            ("Environmental controls (power, cooling, fire suppression) are in place.", 2,
             "Verify for on-prem/datacenter-hosted assets; mark N/A for cloud-only."),
        ],
    },
]


class Command(BaseCommand):
    help = "Seed a default cyber-security risk assessment checklist."

    def handle(self, *args, **options):
        created_categories = 0
        created_questions = 0
        for order, cat in enumerate(CHECKLIST):
            category, was_created = ChecklistCategory.objects.get_or_create(
                name=cat["name"],
                defaults={"description": cat["description"], "order": order},
            )
            if was_created:
                created_categories += 1
            for q_order, (text, weight, guidance) in enumerate(cat["questions"]):
                _, q_created = ChecklistQuestion.objects.get_or_create(
                    category=category,
                    text=text,
                    defaults={"weight": weight, "guidance": guidance, "order": q_order},
                )
                if q_created:
                    created_questions += 1

        self.stdout.write(self.style.SUCCESS(
            f"Seeded checklist: {created_categories} new categories, {created_questions} new questions."
        ))
