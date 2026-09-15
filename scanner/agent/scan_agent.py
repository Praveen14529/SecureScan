"""
Local system vulnerability/risk scanner.

Each check_* function returns a list of finding dicts:
    {category, title, severity, description, evidence, mitigation}

Every check is wrapped so a failure (permissions, missing tool, unsupported
OS) turns into a single "info" finding rather than crashing the scan -
this is what makes it safe to run cross-platform without knowing in
advance what's installed or what privileges the user has.
"""
import platform
import socket
import subprocess
import shutil
import datetime

import psutil

SYSTEM = platform.system()  # 'Windows', 'Linux', 'Darwin'


def _run(cmd, timeout=8):
    """Run a shell command, return stdout text or None on any failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str)
        )
        return result.stdout
    except Exception:
        return None


def _finding(category, title, severity, description, evidence="", mitigation=""):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "mitigation": mitigation,
    }


# --------------------------------------------------------------------- #
# System configuration checks
# --------------------------------------------------------------------- #

def check_os_patch_status():
    findings = []
    if SYSTEM == "Windows":
        out = _run(["powershell", "-NoProfile", "-Command",
                     "Get-HotFix | Sort-Object InstalledOn -Descending | "
                     "Select-Object -First 1 -ExpandProperty InstalledOn"])
        if out and out.strip():
            findings.append(_finding(
                "system", "Windows Update history", "info",
                f"Most recent installed update: {out.strip()}",
                evidence=out.strip(),
                mitigation="Ensure Windows Update is set to install updates automatically.",
            ))
        else:
            findings.append(_finding(
                "system", "Could not determine Windows Update status", "low",
                "Unable to read update history (may need admin rights).",
                mitigation="Manually check Settings > Windows Update for pending updates.",
            ))
    elif SYSTEM == "Linux":
        stamp = _run(["stat", "-c", "%Y", "/var/lib/apt/periodic/update-success-stamp"]) \
            or _run(["stat", "-c", "%Y", "/var/log/dnf.log"])
        if stamp and stamp.strip().isdigit():
            last = datetime.datetime.fromtimestamp(int(stamp.strip()))
            days_ago = (datetime.datetime.now() - last).days
            if days_ago > 60:
                findings.append(_finding(
                    "system", "Package index not updated recently", "medium",
                    f"Last package update check was {days_ago} days ago.",
                    evidence=str(last),
                    mitigation="Run your package manager's update command "
                               "(e.g. `sudo apt update && sudo apt upgrade`) regularly.",
                ))
            else:
                findings.append(_finding(
                    "system", "Package index recently updated", "info",
                    f"Last update check {days_ago} day(s) ago.",
                ))
        else:
            findings.append(_finding(
                "system", "Could not determine patch status", "low",
                "No update timestamp found for this distribution.",
                mitigation="Manually verify OS packages are current with your package manager.",
            ))
    else:  # Darwin / other
        findings.append(_finding(
            "system", "OS patch status not automated on this platform", "info",
            f"Automated patch-level checking isn't implemented for {SYSTEM}.",
            mitigation="Check System Settings > General > Software Update.",
        ))
    return findings


def check_firewall_status():
    findings = []
    if SYSTEM == "Windows":
        out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if out:
            if "OFF" in out.upper():
                findings.append(_finding(
                    "system", "Windows Firewall disabled on one or more profiles", "high",
                    "At least one firewall profile (Domain/Private/Public) is OFF.",
                    evidence=out.strip(),
                    mitigation="Enable Windows Defender Firewall for all profiles: "
                               "Control Panel > Windows Defender Firewall > Turn on.",
                ))
            else:
                findings.append(_finding(
                    "system", "Windows Firewall enabled", "info",
                    "All checked profiles report ON.", evidence=out.strip(),
                ))
        else:
            findings.append(_finding(
                "system", "Could not read firewall status", "low",
                "netsh command failed or was unavailable.",
                mitigation="Manually verify Windows Firewall is enabled.",
            ))
    elif SYSTEM == "Linux":
        if shutil.which("ufw"):
            out = _run(["ufw", "status"])
            if out and "inactive" in out.lower():
                findings.append(_finding(
                    "system", "UFW firewall is inactive", "high",
                    "ufw is installed but not active.", evidence=out.strip(),
                    mitigation="Enable it with `sudo ufw enable` after configuring allowed rules.",
                ))
            elif out:
                findings.append(_finding(
                    "system", "UFW firewall active", "info", "ufw reports active.", evidence=out.strip(),
                ))
        elif shutil.which("firewall-cmd"):
            out = _run(["firewall-cmd", "--state"])
            if out and "running" not in out.lower():
                findings.append(_finding(
                    "system", "firewalld not running", "high",
                    "firewalld is installed but not running.",
                    mitigation="Start and enable it: `sudo systemctl enable --now firewalld`.",
                ))
            else:
                findings.append(_finding(
                    "system", "firewalld running", "info", "firewalld reports running.",
                ))
        else:
            findings.append(_finding(
                "system", "No recognized firewall manager found", "medium",
                "Neither ufw nor firewalld was found on this system.",
                mitigation="Install and enable a firewall (ufw is simplest: `sudo apt install ufw && sudo ufw enable`).",
            ))
    elif SYSTEM == "Darwin":
        out = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if out and "disabled" in out.lower():
            findings.append(_finding(
                "system", "macOS Application Firewall disabled", "high",
                "The built-in firewall is off.", evidence=out.strip(),
                mitigation="Enable it: System Settings > Network > Firewall.",
            ))
        elif out:
            findings.append(_finding(
                "system", "macOS Application Firewall enabled", "info", evidence=out.strip(),
                description="Firewall reports enabled.",
            ))
    return findings


def check_antivirus():
    findings = []
    if SYSTEM == "Windows":
        out = _run(["powershell", "-NoProfile", "-Command",
                     "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
                     "RealTimeProtectionEnabled,AntivirusSignatureAge | Format-List"])
        if out and "AntivirusEnabled" in out:
            disabled = "AntivirusEnabled" in out and "False" in out.split("AntivirusEnabled")[1].split("\n")[0]
            rtp_disabled = "RealTimeProtectionEnabled" in out and \
                "False" in out.split("RealTimeProtectionEnabled")[1].split("\n")[0]
            if disabled or rtp_disabled:
                findings.append(_finding(
                    "system", "Antivirus / real-time protection disabled", "critical",
                    "Windows Defender reports antivirus or real-time protection is off.",
                    evidence=out.strip(),
                    mitigation="Re-enable Windows Defender or confirm a third-party AV is active "
                               "and up to date.",
                ))
            else:
                findings.append(_finding(
                    "system", "Antivirus active", "info",
                    "Windows Defender reports active protection.", evidence=out.strip(),
                ))
        else:
            findings.append(_finding(
                "system", "Could not determine antivirus status", "low",
                "Get-MpComputerStatus unavailable (may be running non-Defender AV, or needs admin rights).",
                mitigation="Manually confirm an antivirus product is installed, active, and updated.",
            ))
    else:
        findings.append(_finding(
            "system", "Automated antivirus check not available on this platform", "info",
            f"No standard AV status API checked for {SYSTEM}.",
            mitigation="Confirm endpoint protection appropriate for your environment is running.",
        ))
    return findings


def check_guest_account():
    findings = []
    if SYSTEM == "Windows":
        out = _run(["net", "user", "guest"])
        if out and "Account active" in out:
            active_line = [l for l in out.splitlines() if "Account active" in l]
            if active_line and "Yes" in active_line[0]:
                findings.append(_finding(
                    "system", "Guest account is enabled", "high",
                    "The built-in Windows Guest account is active.",
                    evidence=active_line[0].strip(),
                    mitigation="Disable it: `net user guest /active:no` (run as Administrator).",
                ))
            else:
                findings.append(_finding(
                    "system", "Guest account disabled", "info", "Guest account is inactive.",
                ))
    return findings


def check_password_policy():
    findings = []
    if SYSTEM == "Windows":
        out = _run(["net", "accounts"])
        if out:
            min_len = None
            for line in out.splitlines():
                if "Minimum password length" in line:
                    digits = "".join(c for c in line.split(":")[-1] if c.isdigit())
                    min_len = int(digits) if digits else None
            if min_len is not None and min_len < 8:
                findings.append(_finding(
                    "system", "Weak minimum password length policy", "medium",
                    f"Local minimum password length is set to {min_len} characters.",
                    evidence=out.strip(),
                    mitigation="Set minimum password length to 8+ via `net accounts /minpwlen:12` "
                               "(run as Administrator) or Local Security Policy.",
                ))
    elif SYSTEM == "Linux":
        out = _run(["cat", "/etc/login.defs"])
        if out:
            min_len = None
            for line in out.splitlines():
                if line.strip().startswith("PASS_MIN_LEN"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        min_len = int(parts[1])
            if min_len is not None and min_len < 8:
                findings.append(_finding(
                    "system", "Weak minimum password length policy", "medium",
                    f"/etc/login.defs sets PASS_MIN_LEN={min_len}.",
                    mitigation="Raise PASS_MIN_LEN to 8+ in /etc/login.defs, or use a PAM pwquality policy.",
                ))
    return findings


# --------------------------------------------------------------------- #
# Network / open ports
# --------------------------------------------------------------------- #

RISKY_PORTS = {
    21: ("FTP", "high", "Unencrypted file transfer; credentials and data travel in plaintext.",
         "Disable FTP or replace with SFTP/FTPS."),
    23: ("Telnet", "critical", "Unencrypted remote shell; credentials sent in plaintext.",
         "Disable Telnet; use SSH instead."),
    135: ("MSRPC", "medium", "Windows RPC endpoint mapper, historically targeted by worms.",
          "Block at the firewall from untrusted networks; restrict to localhost/LAN."),
    139: ("NetBIOS", "medium", "Legacy Windows file-sharing protocol.",
          "Disable NetBIOS over TCP/IP if not required."),
    445: ("SMB", "high", "File sharing protocol; a common target (e.g. EternalBlue-class exploits) "
                          "if exposed beyond the local network.",
          "Ensure SMB is not reachable from the internet; keep OS patched; disable SMBv1."),
    1433: ("MSSQL", "high", "SQL Server listening; exposing a database port directly is risky.",
           "Bind to localhost or a private network only; require strong auth; use a firewall rule."),
    1521: ("Oracle DB", "high", "Oracle listener exposed.",
           "Restrict to trusted hosts/VPN; do not expose to the internet."),
    3306: ("MySQL", "high", "Database port listening; direct exposure risks unauthorized access.",
           "Bind to 127.0.0.1 or a private network; use strong credentials and a firewall rule."),
    3389: ("RDP", "high", "Remote Desktop exposed; a very common brute-force/ransomware entry point.",
           "Require VPN access, enable Network Level Authentication, use MFA, or restrict by IP."),
    5432: ("PostgreSQL", "high", "Database port listening; risky if reachable beyond localhost.",
           "Bind to 127.0.0.1 or private network; enforce strong auth via pg_hba.conf."),
    5900: ("VNC", "high", "Remote screen-sharing; frequently deployed with weak/no authentication.",
           "Use a VPN and strong authentication, or disable if unused."),
    6379: ("Redis", "critical", "Redis often runs without authentication by default; direct exposure "
                                 "can allow full data/host compromise.",
           "Bind to 127.0.0.1, set `requirepass`, and never expose to the internet."),
    27017: ("MongoDB", "critical", "MongoDB has a history of being exposed with no authentication.",
            "Enable authentication, bind to localhost/private network only."),
}


def check_open_ports():
    findings = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        findings.append(_finding(
            "network", "Could not enumerate listening ports", "low",
            "Reading network connections requires elevated privileges on this OS.",
            mitigation="Re-run the scan as Administrator/root for full port visibility.",
        ))
        return findings
    except Exception as e:
        findings.append(_finding(
            "network", "Port scan failed", "low", f"Unexpected error: {e}",
        ))
        return findings

    seen_ports = {}
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        port = c.laddr.port
        addr = c.laddr.ip
        if port in seen_ports:
            continue
        seen_ports[port] = addr
        try:
            proc_name = psutil.Process(c.pid).name() if c.pid else "unknown"
        except Exception:
            proc_name = "unknown"

        exposed = addr not in ("127.0.0.1", "::1", "localhost")

        if port in RISKY_PORTS:
            label, base_severity, desc, mitigation = RISKY_PORTS[port]
            severity = base_severity
            if not exposed:
                # localhost-only reduces (but doesn't remove) the risk
                downgrade = {"critical": "high", "high": "medium", "medium": "low"}
                severity = downgrade.get(base_severity, base_severity)
            findings.append(_finding(
                "network", f"Port {port} ({label}) is open — process: {proc_name}", severity,
                desc + (" Bound to localhost only." if not exposed else " Bound to all interfaces / reachable externally."),
                evidence=f"{addr}:{port} listening, pid process '{proc_name}'",
                mitigation=mitigation,
            ))
        else:
            findings.append(_finding(
                "network", f"Port {port} open — process: {proc_name}", "info",
                f"Listening on {addr}:{port}.",
                evidence=f"{addr}:{port} listening, pid process '{proc_name}'",
                mitigation="Review whether this service needs to be reachable; close if unused.",
            ))
    if not seen_ports:
        findings.append(_finding(
            "network", "No listening ports detected", "info",
            "No LISTEN sockets were found (or visibility is restricted).",
        ))
    return findings


# --------------------------------------------------------------------- #
# Installed software
# --------------------------------------------------------------------- #

def _list_installed_windows():
    software = []
    ps_cmd = (
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName, DisplayVersion "
        "| Where-Object { $_.DisplayName } "
        "| ForEach-Object { \"$($_.DisplayName)||$($_.DisplayVersion)\" }"
    )
    out = _run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if out:
        for line in out.splitlines():
            if "||" in line:
                name, _, version = line.partition("||")
                if name.strip():
                    software.append((name.strip(), version.strip()))
    return software


def _list_installed_linux():
    software = []
    if shutil.which("dpkg-query"):
        out = _run(["dpkg-query", "-W", "-f=${Package}||${Version}\\n"], timeout=20)
        if out:
            for line in out.splitlines():
                if "||" in line:
                    name, _, version = line.partition("||")
                    software.append((name.strip(), version.strip()))
    elif shutil.which("rpm"):
        out = _run(["rpm", "-qa", "--qf", "%{NAME}||%{VERSION}\\n"], timeout=20)
        if out:
            for line in out.splitlines():
                if "||" in line:
                    name, _, version = line.partition("||")
                    software.append((name.strip(), version.strip()))
    return software


def _list_installed_macos():
    software = []
    out = _run(["system_profiler", "SPApplicationsDataType", "-json"], timeout=30)
    if out:
        import json
        try:
            data = json.loads(out)
            for app in data.get("SPApplicationsDataType", []):
                name = app.get("_name", "")
                version = app.get("version", "")
                if name:
                    software.append((name, version))
        except Exception:
            pass
    return software


# Small curated table of well-known EOL/high-risk software - name substrings
# (lowercase) mapped to a note. This is intentionally conservative: it flags
# unmistakably end-of-life or historically high-risk software rather than
# trying to do full version-range CVE matching offline.
KNOWN_RISKY_SOFTWARE = [
    ("adobe flash", "critical", "Adobe Flash Player reached end-of-life in Dec 2020 and is no longer "
                                 "patched; it is a well-known high-severity attack vector.",
     "Uninstall Adobe Flash Player entirely; it should not be present on any system."),
    ("python 2", "high", "Python 2 reached end-of-life in Jan 2020 and no longer receives security patches.",
     "Migrate to Python 3 and uninstall Python 2 if not required by legacy software."),
    ("java 6", "high", "Java 6 is long past end-of-life.", "Upgrade to a current, supported JDK/JRE."),
    ("java 7", "high", "Java 7 is past end-of-life.", "Upgrade to a current, supported JDK/JRE."),
    ("windows xp", "critical", "Windows XP is unsupported and receives no security updates.",
     "Upgrade the OS; do not connect an XP machine to untrusted networks."),
    ("windows 7", "high", "Windows 7 is past mainstream end-of-life and no longer receives free security updates.",
     "Upgrade to a supported Windows version."),
    ("teamviewer", "low", "Remote access tools are frequently abused if left with default/weak settings.",
     "Ensure strong authentication and that unattended access isn't left enabled unnecessarily."),
]


def check_installed_software(deep_cve_lookup=False):
    findings = []
    if SYSTEM == "Windows":
        software = _list_installed_windows()
    elif SYSTEM == "Linux":
        software = _list_installed_linux()
    elif SYSTEM == "Darwin":
        software = _list_installed_macos()
    else:
        software = []

    if not software:
        findings.append(_finding(
            "software", "Could not enumerate installed software", "low",
            f"No installed-software listing available for {SYSTEM} in this environment "
            "(may need elevated privileges or an unsupported package manager).",
            mitigation="Manually review installed applications for outdated or unnecessary software.",
        ))
        return findings

    findings.append(_finding(
        "software", f"{len(software)} installed software entries scanned", "info",
        "Baseline inventory collected for risk pattern matching.",
    ))

    matched_names = set()
    for name, version in software:
        lname = name.lower()
        for pattern, severity, desc, mitigation in KNOWN_RISKY_SOFTWARE:
            if pattern in lname and name not in matched_names:
                matched_names.add(name)
                findings.append(_finding(
                    "software", f"Risky/EOL software detected: {name} {version}".strip(), severity,
                    desc, evidence=f"{name} {version}", mitigation=mitigation,
                ))

    if deep_cve_lookup:
        findings.extend(_nvd_lookup_top_software(software))

    return findings


def _nvd_lookup_top_software(software, limit=5):
    """Best-effort keyword search against the NVD API for a handful of
    installed applications. Keyword search (not precise CPE matching), so
    results may include false positives - always labeled as such."""
    findings = []
    try:
        import requests
    except ImportError:
        findings.append(_finding(
            "software", "Deep CVE lookup skipped", "info",
            "The 'requests' package is not installed, so live NVD lookups were skipped.",
            mitigation="Install with `pip install requests` to enable this feature.",
        ))
        return findings

    # Skip very generic/common names that would return noisy, useless results.
    generic = {"update", "redistributable", "driver", "runtime", "helper", "service"}
    candidates = [
        (n, v) for n, v in software
        if len(n) > 3 and not any(g in n.lower() for g in generic)
    ][:limit]

    for name, version in candidates:
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": name, "resultsPerPage": 3},
                timeout=10,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "Unknown CVE")
                descs = cve.get("descriptions", [])
                desc_text = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                severity = "medium"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        base_severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "")
                        severity = base_severity.lower() if base_severity else severity
                findings.append(_finding(
                    "software", f"Possible CVE match for {name}: {cve_id}", severity,
                    desc_text[:400],
                    evidence=f"NVD keyword search on '{name}' {version} — verify applicability manually.",
                    mitigation="Confirm this CVE actually applies to your installed version, then "
                               "update the software or apply the vendor's patch.",
                ))
        except Exception:
            continue

    if not findings:
        findings.append(_finding(
            "software", "Deep CVE lookup completed", "info",
            "No keyword matches returned from NVD for the sampled software (or lookup failed/offline).",
        ))
    return findings


# --------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------- #

def run_full_scan(deep_cve_lookup=False):
    """Runs every check and returns (hostname, os_summary, findings_list)."""
    all_findings = []
    for check in (check_os_patch_status, check_firewall_status, check_antivirus,
                  check_guest_account, check_password_policy):
        try:
            all_findings.extend(check())
        except Exception as e:
            all_findings.append(_finding("system", f"{check.__name__} failed", "low", str(e)))

    try:
        all_findings.extend(check_open_ports())
    except Exception as e:
        all_findings.append(_finding("network", "Port scan failed", "low", str(e)))

    try:
        all_findings.extend(check_installed_software(deep_cve_lookup=deep_cve_lookup))
    except Exception as e:
        all_findings.append(_finding("software", "Software scan failed", "low", str(e)))

    hostname = socket.gethostname()
    os_summary = f"{platform.system()} {platform.release()} ({platform.version()})"
    return hostname, os_summary, all_findings


# --------------------------------------------------------------------- #
# Standalone CLI — everything above this line mirrors scanner/engine.py.
# This section turns it into a downloadable, dependency-light scanner
# that runs on the visitor's own machine and submits results to the
# SecureScan web dashboard, where they can view/export the report.
# --------------------------------------------------------------------- #

def _print_banner():
    print("=" * 60)
    print(" SecureScan — local vulnerability scanner")
    print(" This runs entirely on YOUR machine. Findings are only")
    print(" sent to the server you specify, and only when the scan")
    print(" finishes. Nothing is sent to any third party.")
    print("=" * 60)


def _print_findings_summary(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"\nScan complete — {len(findings)} findings:")
    print(f"  Critical: {counts['critical']}   High: {counts['high']}   "
          f"Medium: {counts['medium']}   Low: {counts['low']}   Info: {counts['info']}")
    for f in sorted(findings, key=lambda x: -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[x["severity"]]):
        if f["severity"] in ("critical", "high"):
            print(f"  [{f['severity'].upper():8}] {f['title']}")


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="SecureScan local vulnerability scanner")
    parser.add_argument("--server", default="__SERVER_URL__",
                         help="SecureScan server base URL to submit results to")
    parser.add_argument("--label", default="", help="Optional label for this scan (e.g. 'Work laptop')")
    parser.add_argument("--deep-cve", action="store_true",
                         help="Enable best-effort live NVD keyword lookup for installed software "
                              "(requires internet, slower, more false positives)")
    parser.add_argument("--no-submit", action="store_true",
                         help="Run the scan and print results locally without submitting anywhere")
    parser.add_argument("--no-browser", action="store_true",
                         help="Don't automatically open the report in a browser after submitting")
    args = parser.parse_args()

    _print_banner()
    print(f"\nScanning {platform.system()} {platform.release()}... this can take a minute.\n")

    hostname, os_summary, findings = run_full_scan(deep_cve_lookup=args.deep_cve)
    _print_findings_summary(findings)

    if args.no_submit:
        print("\n--no-submit set: results were not sent anywhere.")
        return

    try:
        import requests
    except ImportError:
        print("\nThe 'requests' package is needed to submit results. Install it with:")
        print("  pip install requests")
        print("Or re-run with --no-submit to just see results in this terminal.")
        return

    payload = {
        "hostname": hostname,
        "os_summary": os_summary,
        "deep_cve_lookup": args.deep_cve,
        "client_label": args.label,
        "findings": findings,
    }

    server = args.server.rstrip("/")
    print(f"\nSubmitting results to {server} ...")
    try:
        resp = requests.post(f"{server}/api/scans/submit/", json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        report_url = data.get("report_url")
        print(f"\nReport ready: {report_url}")
        if not args.no_browser and report_url:
            import webbrowser
            webbrowser.open(report_url)
    except Exception as e:
        print(f"\nCould not submit results: {e}")
        print("Your findings were still printed above — nothing is lost.")


if __name__ == "__main__":
    main()
