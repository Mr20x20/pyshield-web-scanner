# ARCHITECTURE.md — PyShield Web Security Scanner

This document explains the purpose of every file, why key functions exist,
and what would break if each component were removed.

---

## Why This Project Exists

Web servers are frequently misconfigured — developers leave debug files,
forget to set security headers, or expose admin panels accidentally.
These misconfigurations are the most common entry points for real attacks,
yet they require no exploitation — just knowing where to look.

This scanner automates that process: given a URL, it checks every known
misconfiguration pattern and produces a scored risk report.

---

## File-by-File Breakdown

---

### `config.py`
**Purpose:** Single source of truth for all settings, rules, and constants.

**Why it matters:**
Every other module imports from `config.py`. Timeouts, paths to check,
header names, severity scores — all defined here once.

**Key contents:**
- `EXPOSED_PATHS` — list of 40 sensitive paths with severity per path
- `SECURITY_HEADERS` — headers that must be present
- `LEAKY_HEADERS` — headers that must NOT be present
- `SEVERITY_SCORES` — maps CRITICAL/HIGH/MEDIUM/LOW to point values
- `RISK_LEVELS` — score thresholds for risk level labels

**What breaks if removed:**
Everything. Every module imports from here. The scanner cannot start.

**What breaks if a path is removed from `EXPOSED_PATHS`:**
That specific misconfiguration will never be detected, silently producing
false negatives. For example, removing `/.env` means exposed environment
files are never reported.

---

### `http_client.py`
**Purpose:** Centralized HTTP session shared across all check modules.

**Why it matters:**
Without centralization, each check module would create its own
`requests.Session()` with potentially different headers, timeouts,
and SSL settings — producing inconsistent results.

**Key classes and functions:**

`class HTTPClient`
- Owns one `requests.Session` for the entire scan
- All checks call `client.get()` or `client.get_headers_only()`
- Ensures every request uses the same User-Agent, timeout, and SSL settings

`class Response` (dataclass)
- Wraps raw `requests.Response` into a clean interface
- Properties: `ok`, `is_success`, `is_forbidden`, `is_not_found`
- `header(name)` — case-insensitive header lookup
- Hides `requests` internals from check modules — if we switch HTTP
  libraries, only `http_client.py` changes

`_normalize_url()`
- Handles missing scheme (`example.com` → `http://example.com`)
- Strips trailing slashes for consistent path concatenation
- Lowercases hostname

**What breaks if removed:**
All check modules break — they all import `HTTPClient`.

**What breaks if `_normalize_url()` is removed:**
URLs like `example.com/admin` or `https://Example.COM/` would produce
incorrect path concatenation and inconsistent results.

**What breaks if `Response.header()` is removed:**
`headers.py` would need to manually lowercase every header lookup.
HTTP header case-insensitivity would cause missed findings.

---

### `discovery.py`
**Purpose:** Gather intelligence about the target before checks run.

**Why it matters:**
`robots.txt` often lists paths the site owner wants hidden — admin panels,
backup directories, private APIs. These are exactly the paths attackers
look for. Discovery feeds this intelligence into the scan context.

**Key functions:**

`run(client)` → dict
- Fetches root page, robots.txt, sitemap.xml
- Returns: title, server, redirect chain, robots paths, technologies

`_parse_robots(body)`
- Extracts `Disallow:` lines from robots.txt
- These are paths the site explicitly wants hidden — high-value targets
- Returns deduplicated list of paths

`_detect_technologies(response)`
- Fingerprints technology stack from headers and body
- Detects: WordPress, Django, Laravel, React, PHP, nginx, Apache etc.
- Uses: Server header, X-Powered-By, body signatures, cookie names

**What breaks if removed:**
- `run.py` crashes (import error)
- Technology detection disappears from reports
- robots.txt paths are never discovered

**What breaks if `_detect_technologies()` is removed:**
Technology stack never appears in reports. Scans of WordPress sites
would not flag WordPress-specific paths as higher priority.

---

### `checks/exposed_files.py`
**Purpose:** Check 40 sensitive paths for public accessibility.

**Why it matters:**
A single exposed `.env` file can contain database credentials, AWS keys,
and API tokens — complete system compromise from one misconfiguration.
This is the highest-impact check in the scanner.

**Key functions:**

`run(client)` → list[dict]
- Uses `ThreadPoolExecutor(max_workers=10)` to check paths concurrently
- Without threading: 40 paths × 3s timeout = up to 2 minutes
- With threading: ~15-20 seconds total

`_check_path(client, path, description, severity)`
- Status 200 → exposed, extract evidence
- Status 401 → exists but auth-protected, downgrade severity
- Status 403 → exists but forbidden, keep finding for CRITICAL/HIGH paths
- Status 404 → not found, no finding

`_extract_evidence(path, body)`
- For `.env`: extracts key names (never values) — shows `DB_PASSWORD` not the actual password
- For `.git/HEAD`: shows branch reference
- For phpinfo: extracts PHP version string

`_downgrade_severity(severity)`
- Drops severity one level (CRITICAL→HIGH, HIGH→MEDIUM etc.)
- Used for 401 responses — resource exists but is protected

**What breaks if removed:**
Exposed file detection disappears entirely — the most critical check
is gone. `.env`, `.git`, phpinfo, admin panels are never checked.

**What breaks if threading is removed:**
Scanner still works but becomes very slow — 2+ minutes just for this check.

**What breaks if `_extract_evidence()` is removed:**
Findings still appear but with no evidence snippet — harder to verify
and less convincing in reports.

---

### `checks/headers.py`
**Purpose:** Analyze HTTP security headers on the target's root page.

**Why it matters:**
Security headers are the browser's last line of defense against many
attack classes. CSP prevents XSS, HSTS prevents downgrade attacks,
X-Frame-Options prevents clickjacking. Missing headers = no browser defense.

**Key functions:**

`run(client)` → list[dict]
- Two separate check types in one pass: missing security headers and leaky informational headers
- Uses `get_headers_only()` (HEAD request) — faster, no body needed

`_check_header_value(header, value)`
- Validates that present headers are configured correctly
- CSP with `unsafe-inline` is present but useless — still flagged
- HSTS with `max-age=0` is present but disabled — still flagged
- Without this: a misconfigured header would appear as "OK"

`_get_recommendation(header)`
- Returns exact fix for each missing header
- Example: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
- Makes the report actionable, not just a list of problems

**What breaks if removed:**
All header analysis disappears. Missing CSP, HSTS, X-Frame-Options
are never detected — significant findings missed.

**What breaks if `_check_header_value()` is removed:**
Headers present but misconfigured (e.g. CSP with `unsafe-inline`) pass
silently — false negatives for weak configurations.

---

### `checks/tls.py`
**Purpose:** Validate TLS certificate validity and configuration.

**Why it matters:**
An expired certificate breaks HTTPS for all users. A hostname mismatch
means the certificate doesn't actually protect the domain being scanned.
A self-signed certificate means no trusted CA has verified the identity.

**Key functions:**

`run(host)` → list[dict]
- Only called for HTTPS targets (run.py checks scheme first)
- Fetches cert with `ssl.CERT_NONE` — inspects even broken certificates

`_get_cert_info(host)`
- Connects to port 443 and retrieves certificate + cipher + TLS version
- Uses `CERT_NONE` deliberately — we need to see the cert even if invalid
- If we used normal verification, expired certs would crash before we report them

`_check_expiry(host, cert_info)`
- Two thresholds: WARNING (30 days) and CRITICAL (7 days)
- Parses SSL date format: `"Dec 31 23:59:59 2024 GMT"`

`_check_self_signed(host, cert_info)`
- Compares subject CN to issuer CN
- Self-signed: they are identical (the cert signed itself)

**What breaks if removed:**
TLS checks disappear. Expired certificates, hostname mismatches,
and self-signed certs are never detected.

**What breaks if `ssl.CERT_NONE` is changed to `ssl.CERT_REQUIRED`:**
The scanner crashes on any invalid certificate before it can report
the problem — the opposite of what we want.

---

### `checks/directory.py`
**Purpose:** Detect directories with listing enabled.

**Why it matters:**
Directory listing lets anyone browse folder contents like a file manager.
An exposed `/uploads/` directory can reveal every file users ever uploaded,
including private documents, backup files, and configuration files.

**Key functions:**

`run(client)` → list[dict]
- Uses `ThreadPoolExecutor(max_workers=5)` — 12 paths checked concurrently

`_detect_listing(body)`
- Checks response body for known directory listing HTML signatures
- Signatures: "Index of /", "Directory listing for", "Parent Directory"
- Different web servers use different text — we check all known variants

`_get_severity(path)`
- `/backup/`, `/logs/`, `/data/` → CRITICAL (sensitive content expected)
- `/uploads/`, `/files/` → HIGH (user content)
- Everything else → MEDIUM

**What breaks if removed:**
Directory listing detection disappears entirely.

**What breaks if `_detect_listing()` only checks one signature:**
Some web servers (nginx, IIS) use different listing HTML than Apache.
Checking only "Index of /" would miss nginx and IIS directory listings.

---

### `risk_engine.py`
**Purpose:** Score all findings and determine overall risk level.

**Why it matters:**
Raw findings are a flat list with no priority. The risk engine converts
them into a single score and risk level — the number a manager or
developer can act on immediately without reading every finding.

**Key functions:**

`assess(target, all_findings, discovery)` → dict
- Sums `SEVERITY_SCORES` for each finding
- Sorts findings: CRITICAL first, then HIGH, MEDIUM, LOW
- Calls `_build_summary()` for human-readable output

`_get_risk_level(score)`
- Uses `RISK_LEVELS` threshold list from config
- Thresholds are higher than the SIEM because this is a point-in-time
  scan, not a continuous event stream

`_build_summary()`
- Produces bullet-point summary matching PyShield ecosystem format
- Top 3 CRITICAL findings called out explicitly

**What breaks if removed:**
`run.py` crashes. No scoring, no risk level, no summary.

**What breaks if `SEVERITY_SCORES` weights are changed in config:**
Risk levels shift — a scan that was HIGH may become MEDIUM or CRITICAL.
Weights should be adjusted carefully based on real-world impact.

---

### `reporter.py`
**Purpose:** Write JSON report and print terminal summary.

**Why it matters:**
The JSON report is what the PyShield Dashboard reads. The terminal
summary is what the user reads. Both are required for the tool to
be useful.

**Key functions:**

`write(report)`
- Writes full report dict to `reports/web_scan_report.json`
- This file is consumed by PyShield Dashboard as a sensor source

`print_summary(report)`
- Formatted terminal output with aligned columns
- Shows top findings sorted by severity

**What breaks if removed:**
No output — scan runs but results are never saved or displayed.

**What breaks if `write()` is removed:**
Dashboard integration breaks — no JSON file for the SIEM to read.

---

## Data Flow Summary

```
run.py
  │
  ├── HTTPClient(target)          # one shared session
  │
  ├── discovery.run(client)       # robots.txt, tech stack
  │
  ├── exposed_files.run(client)   # 40 paths, threaded
  ├── headers.run(client)         # 6 security + leaky headers
  ├── tls.run(hostname)           # cert validity
  ├── directory.run(client)       # 12 dirs, threaded
  │
  ├── risk_engine.assess(...)     # score + sort + summarize
  │
  └── reporter.write(report)      # JSON + terminal output
           │
           └── reports/web_scan_report.json
                      │
                      └── PyShield Dashboard (SIEM)
```

---

## Design Decisions

**Why `checks/` is a package not a single file:**
Each check type is independent — you can add a new check (e.g. cookie
security) by adding one file to `checks/` and one line in `run.py`.
No existing code changes needed.

**Why threading in exposed_files and directory but not headers/tls:**
Headers and TLS make 1-2 requests each — threading adds no benefit.
Exposed files and directory make 40+ and 12+ requests respectively —
threading cuts runtime from minutes to seconds.

**Why `VERIFY_SSL = False` in config:**
TLS validation is done manually in `tls.py`. If requests validated SSL,
sites with expired or self-signed certs would crash the scanner before
we could report those issues. Disabling it in requests and checking
manually gives us full control.

**Why `Response` is a dataclass wrapper:**
Decouples the rest of the codebase from `requests`. If we ever replace
`requests` with `httpx` or another library, only `http_client.py` changes.
All check modules continue to work unchanged.
