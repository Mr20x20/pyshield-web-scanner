# 🌐 PyShield Web Security Scanner

A web misconfiguration scanner that checks a target URL for common security weaknesses — exposed sensitive files, missing security headers, TLS certificate issues, and directory listing. Part of the **PyShield** security ecosystem.

---

## 📸 Example Output

```
============================================================
  PyShield Web Security Scanner — Results
============================================================
  Target     : https://example.com
  Risk Score : 50
  Risk Level : HIGH
------------------------------------------------------------
  Findings   : 7 total | CRITICAL:0 HIGH:2 MEDIUM:2 LOW:3
------------------------------------------------------------
  Server     : cloudflare
  Page Title : Example Domain
------------------------------------------------------------
  FINDINGS:
  [HIGH    ] Missing: HSTS — forces HTTPS connections
  [HIGH    ] Missing: CSP — prevents XSS and injection attacks
  [MEDIUM  ] Missing: Prevents clickjacking attacks
  [LOW     ] Information disclosure: Reveals web server software
============================================================
```

---

## 🏗️ Architecture

```
Target URL
    │
    ▼
┌─────────────────┐
│  http_client.py │  Centralized HTTP session, response wrapper
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  discovery.py   │  robots.txt, sitemap.xml, tech detection
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│                  checks/                    │
│  ┌─────────────────┐  ┌──────────────────┐ │
│  │ exposed_files.py│  │   headers.py     │ │
│  │ .env, .git,     │  │ CSP, HSTS,       │ │
│  │ phpinfo, admin  │  │ X-Frame-Options  │ │
│  └─────────────────┘  └──────────────────┘ │
│  ┌─────────────────┐  ┌──────────────────┐ │
│  │    tls.py       │  │  directory.py    │ │
│  │ cert expiry,    │  │ listing enabled  │ │
│  │ self-signed     │  │ on directories   │ │
│  └─────────────────┘  └──────────────────┘ │
└────────────────────┬────────────────────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │   risk_engine.py    │  Weighted scoring → risk level
          └──────────┬──────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │    reporter.py      │  JSON report + terminal summary
          └──────────┬──────────┘
                     │
                     ▼
          web_scan_report.json  ←── PyShield SIEM Dashboard
```

---

## 🔍 What It Checks

### Exposed Sensitive Files (40 paths)
Files that should never be publicly accessible:

| Path | Risk | Why Dangerous |
|---|---|---|
| `/.env` | CRITICAL | Contains DB passwords, API keys |
| `/.git/config` | CRITICAL | Exposes source code repository |
| `/phpinfo.php` | HIGH | Reveals PHP config, server paths |
| `/wp-admin/` | HIGH | WordPress admin panel |
| `/phpmyadmin/` | HIGH | Database admin interface |
| `/backup.sql` | MEDIUM | Database dump |
| `/robots.txt` | LOW | Reveals hidden paths |

### Security Headers
Headers that protect users from common attacks:

| Header | Missing = Risk |
|---|---|
| `Strict-Transport-Security` | Allows HTTP downgrade attacks |
| `Content-Security-Policy` | XSS attacks have no browser defense |
| `X-Frame-Options` | Clickjacking attacks possible |
| `X-Content-Type-Options` | MIME sniffing attacks |

Headers that should NOT be present:

| Header | Risk |
|---|---|
| `Server: nginx/1.18.0` | Tells attackers exact CVEs to search |
| `X-Powered-By: PHP/8.1` | Reveals backend technology |

### TLS Certificate
- Certificate expiry (warning at 30 days, critical at 7)
- Hostname mismatch
- Self-signed certificate detection

### Directory Listing
Checks 12 common directories for enabled listing — if `/uploads/` shows its contents, attackers can enumerate all uploaded files.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Mr20x20/pyshield-web-scanner.git
cd pyshield-web-scanner
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run a scan

```bash
# Scan any target URL
python run.py https://example.com

# HTTP target
python run.py http://192.168.1.1

# Local development server
python run.py http://127.0.0.1:8080
```

---

## 📁 Project Structure

```
pyshield-web-scanner/
├── run.py               # Entry point — orchestrates full pipeline
├── http_client.py       # Centralized HTTP client + response wrapper
├── discovery.py         # Endpoint discovery and tech detection
├── risk_engine.py       # Scoring engine + risk level assessment
├── reporter.py          # Terminal summary + JSON report writer
├── config.py            # All settings, paths, and rules in one place
├── checks/
│   ├── exposed_files.py # Sensitive file/directory checks (threaded)
│   ├── headers.py       # Security header analysis
│   ├── tls.py           # TLS/SSL certificate validation
│   └── directory.py     # Directory listing detection (threaded)
├── requirements.txt
└── reports/             # Auto-created — scan output
    └── web_scan_report.json
```

---

## ⚙️ Configuration

All settings in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `REQUEST_TIMEOUT` | 3s | Per-request timeout |
| `USER_AGENT` | PyShield-Scanner/1.0 | Scanner identification |
| `TLS_EXPIRY_WARNING` | 30 days | Warn before cert expires |
| `TLS_EXPIRY_CRITICAL` | 7 days | Critical cert expiry threshold |

---

## 📊 Risk Scoring

| Severity | Points | Example |
|---|---|---|
| CRITICAL | +25 | `.env` file exposed |
| HIGH | +15 | Missing HSTS header |
| MEDIUM | +7 | Missing X-Frame-Options |
| LOW | +2 | Server header present |

| Total Score | Risk Level |
|---|---|
| 0 | CLEAN |
| 1–10 | LOW |
| 11–30 | MEDIUM |
| 31–60 | HIGH |
| 60+ | CRITICAL |

---

## 🔗 SIEM Integration

Output `web_scan_report.json` is compatible with the
[PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard)
pipeline as a sensor source.

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **HTTP:** `requests`
- **TLS:** Python `ssl` (standard library)
- **Concurrency:** `concurrent.futures.ThreadPoolExecutor`

---

## 🔐 Legal & Ethical Notice

Only scan systems you own or have **explicit written permission** to test.
Unauthorized scanning may be illegal in your jurisdiction.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Mr20x20** — Network & Security Enthusiast
GitHub: [github.com/Mr20x20](https://github.com/Mr20x20)

---

## 🔗 Related Projects

- [PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard) — Real-time SIEM dashboard
- [PyShield Honeypot](https://github.com/Mr20x20/pyshield-honeypot) — Attacker profiler
- [PyShield Threat Intel](https://github.com/Mr20x20/pyshield-threat-intel) — CVE vulnerability scanner
