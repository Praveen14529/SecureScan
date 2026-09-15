# SecureScan

A Django web app with two parts:

1. **Vulnerability Scanner** (the homepage) — a public-facing tool: visitors
   download a small local scanner script, run it on their own machine
   (Windows/Linux/macOS), and it submits results to this web app, where they
   get a risk-scored report with mitigations and PDF/Word export.
2. **Risk Register** (`/risk-register/`) — the original manual checklist-based
   asset risk assessment tool.
   
<img width="1917" height="1000" alt="image" src="https://github.com/user-attachments/assets/4c5b67a3-42e0-4688-86af-51dd7eeb3bd8" />

## Why it's structured this way

A website cannot read another computer's installed software, open ports, or
OS patch level — that's outside a browser's sandbox. So "scan your PC from
our website" only works as: **download a script → it runs locally on the
visitor's machine → it posts results to us → we render the report.** That's
exactly what happens here:

- `scanner/engine.py` — the actual scanning logic (pure Python + psutil, no
  Django dependency).
- `scanner/agent/scan_agent.py` — `engine.py` plus a small CLI wrapper. This
  is the file visitors download from `/download/`. It's regenerated with the
  correct server URL baked in at download time (see `views.download_agent`).
- `POST /api/scans/submit/` — public, unauthenticated JSON endpoint the
  agent posts findings to. Validated, size-capped, and rate-limited
  (5 submissions/minute/IP) since anyone can call it.
- Every scan gets a random **UUID** (`ScanRun.public_id`), not a sequential
  ID — so a report link can't be guessed or enumerated, and one visitor
  can't browse another's exposed ports or installed software list by
  changing a number in the URL.
- There's no login system. Each browser's own scan history (on the
  homepage) is tracked via a **session** — not a public global list — so
  visitors only see scans they created or opened, never everyone's.

If you regenerate the agent, keep `scanner/agent/scan_agent.py` and
`scanner/engine.py` in sync (or edit `engine.py` and re-`cat` it into the
agent file, then re-append the CLI section at the bottom).

## Running locally

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

python manage.py migrate
python manage.py seed_checklist   # loads the Risk Register's default checklist
python manage.py createsuperuser  # optional, for /admin/

python manage.py runserver
```

Open http://127.0.0.1:8000/ — that's the scanner homepage. Click "Download
scanner" to get `scan_agent.py` with `http://127.0.0.1:8000` already baked
in as its submit target, then run `python scan_agent.py` in another
terminal to see the whole loop (needs `pip install psutil requests` in
whatever environment runs the agent — it does **not** need Django).

## Deploying publicly

This is a normal Django app, deployable anywhere that runs Python
(Render, Railway, Fly.io, a VPS, etc.). Using Render as an example:

1. Push this project to a GitHub repo.
2. Create a new Render **Web Service** from that repo.
   - Build command: `pip install -r requirements.txt && python manage.py collectstatic --noinput`
   - Start command is picked up from the `Procfile` (`gunicorn core.wsgi:application`)
3. Set environment variables:
   - `DJANGO_SECRET_KEY` — a long random string (don't reuse the dev one)
   - `DJANGO_DEBUG` = `False`
   - `DJANGO_ALLOWED_HOSTS` = `yourapp.onrender.com` (your actual domain)
   - `DJANGO_CSRF_TRUSTED_ORIGINS` = `https://yourapp.onrender.com`
   - `DATABASE_URL` — add a Render Postgres instance and it's picked up
     automatically (falls back to SQLite if unset, but SQLite doesn't
     persist across deploys on most PaaS — use Postgres for anything real)
4. Deploy. Visit your domain, click "Download scanner", and run it — the
   agent will submit to your real public URL automatically.

**Before making this public**, know the limits and consider hardening:

- The rate limiter uses Django's default in-memory cache, which is
  per-process — on a multi-worker/multi-dyno deployment it won't share
  state, so effective limits are looser than advertised. For real abuse
  resistance, put this behind a shared cache (Redis) or a proxy-level rate
  limiter (Cloudflare, etc.).
- Anyone can `POST` to `/api/scans/submit/` with fabricated data — it's
  validated and size-capped, but there's no proof a submission came from a
  real scan. Fine for a portfolio/community tool; add an API key or
  CAPTCHA-gated download if you need stronger guarantees.
- Findings are stored indefinitely with no expiry or deletion flow.
  Consider adding a scheduled cleanup (e.g. delete scans older than N days)
  if you're hosting this long-term.
- The "Try a live demo" button on the homepage scans **the server itself**,
  clearly labeled as such — it's there so visitors can see a sample report
  before downloading anything, not a stand-in for scanning their own PC.

## What the scanner actually checks

- **System configuration**: OS patch/update status, firewall enabled,
  antivirus/real-time protection status (Windows), guest account enabled
  (Windows), minimum password length policy.
- **Network**: every listening port, cross-referenced against a table of
  commonly-risky ports (Telnet, FTP, RDP, SMB, exposed databases, VNC,
  etc.), flagging higher severity if bound to all interfaces vs.
  localhost-only.
- **Installed software**: enumerates installed packages/programs per OS and
  flags known end-of-life/high-risk software. An optional "Deep CVE lookup"
  does a best-effort live keyword search against the NVD API — needs
  internet, and is keyword-based (not precise CPE matching), so treat
  matches as leads to verify, not certainties.

Every check is wrapped so a missing tool, unsupported OS, or lack of admin
privileges degrades to a low-severity "could not determine" finding instead
of crashing the scan.

Scoring: each finding contributes fixed points by severity (Critical +25,
High +15, Medium +8, Low +3, Info +0), summed and capped at 100 — see
`scanner/models.py` (`SEVERITY_POINTS`) and `scanner/engine.py`
(`RISKY_PORTS`, `KNOWN_RISKY_SOFTWARE`) to change checks or weighting.

**Some checks need elevated privileges** for full visibility. Users should
run the agent as Administrator (Windows) or with `sudo` (Linux/macOS) for
the most complete results.

---

## Risk Register (manual assessment tool)

### How scoring works

- Each checklist question has a **weight (1–5)** reflecting how important
  that control is.
- Each question is answered on a 0–3 scale: Non-compliant, Partially
  compliant, Largely compliant, Fully compliant.
- **Compliance %** = weighted average of answers across all questions
  actually answered.
- **Base risk score** = `100 - compliance %`.
- **Final risk score** = base risk score × a criticality multiplier for the
  asset (Low 0.7, Medium 1.0, High 1.3, Critical 1.6), capped at 100. So the
  same checklist gaps produce a higher risk score on a critical asset than
  on a low-criticality one.
- **Risk level**: Low (0–25), Medium (25–50), High (50–75), Critical (75–100).

All of this lives in `assessments/models.py` (`Assessment.compliance_percentage`,
`base_risk_score`, `risk_score`, `risk_level`) — tweak the multipliers,
weights, or thresholds there if you want different behavior.

### What's included

- **Assets** (`/risk-register/assets/`) — register systems/apps/databases
  with an owner and a criticality rating.
- **Assessments** — start an assessment against an asset, fill out the
  checklist (grouped by category, with evidence notes per question), save
  progress, and mark it completed.
- **Dashboard** (`/risk-register/`) — every assessment with score, level,
  and filters by status/criticality.
- **Report exports** — PDF or Word (.docx) report with the score, category
  breakdown, and full checklist detail.
- **Django admin** (`/admin/`) — manage checklist categories/questions
  without touching code.

### Customizing the checklist

The default checklist (Access Control, Network Security, Data Protection,
Vulnerability & Patch Management, Incident Response, Physical Security) is
defined in `assessments/management/commands/seed_checklist.py`. Edit that
file and re-run `python manage.py seed_checklist` to add more questions, or
just use `/admin/` to edit categories and questions directly.

## Project layout

```
riskassessment_tool/
├── core/                   # Django project settings/urls
├── assessments/            # Risk Register app (manual checklist tool)
│   ├── models.py             # Asset, ChecklistCategory/Question, Assessment, scoring
│   ├── views.py               # dashboard, asset CRUD, assessment fill/detail, exports
│   ├── reports.py             # PDF (reportlab) and Word (python-docx) report generation
│   ├── forms.py, admin.py, templates/assessments/  (also holds the shared base.html)
│   └── management/commands/seed_checklist.py
└── scanner/                # Vulnerability Scanner app (public product)
    ├── engine.py              # All scanning logic (checks, port table, software rules)
    ├── agent/scan_agent.py    # Standalone downloadable version of engine.py + CLI
    ├── models.py              # ScanRun (with UUID public_id), Finding, scoring
    ├── views.py               # homepage, demo scan, report pages, download, submit API
    ├── reports.py             # PDF/Word report generation
    └── admin.py, urls.py, templates/scanner/
```
