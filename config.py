"""
config.py — PyShield Web Security Scanner
Central configuration. All other modules import from here.
"""

from pathlib import Path

# ── Project root ──────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.resolve()
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── Output ────────────────────────────────────────────────────────────────────
REPORT_FILE = REPORTS_DIR / "web_scan_report.json"

# ── HTTP Client ───────────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 3    # seconds per request
MAX_REDIRECTS     = 5
USER_AGENT        = (
    "Mozilla/5.0 (compatible; PyShield-Scanner/1.0; "
    "security-research)"
)
VERIFY_SSL        = False  # we check SSL ourselves in tls.py

# ── Exposed files to check ────────────────────────────────────────────────────
# These are paths commonly left exposed by misconfigured servers.
# Each tuple: (path, description, severity)
EXPOSED_PATHS = [
    # Critical — direct credential/source exposure
    ("/.env",                    "Environment file",          "CRITICAL"),
    ("/.env.backup",             "Environment backup",        "CRITICAL"),
    ("/.env.local",              "Local environment file",    "CRITICAL"),
    ("/.env.production",         "Production env file",       "CRITICAL"),
    ("/.git/config",             "Git repository config",     "CRITICAL"),
    ("/.git/HEAD",               "Git HEAD reference",        "CRITICAL"),

    # High — source code, config, admin access
    ("/phpinfo.php",             "PHP info page",             "HIGH"),
    ("/info.php",                "PHP info page",             "HIGH"),
    ("/wp-admin/",               "WordPress admin panel",     "HIGH"),
    ("/admin/",                  "Admin panel",               "HIGH"),
    ("/administrator/",          "Admin panel",               "HIGH"),
    ("/phpmyadmin/",             "phpMyAdmin panel",          "HIGH"),
    ("/adminer.php",             "Adminer DB panel",          "HIGH"),
    ("/config.php",              "PHP config file",           "HIGH"),
    ("/configuration.php",       "Configuration file",        "HIGH"),
    ("/wp-config.php",           "WordPress config",          "HIGH"),
    ("/web.config",              "IIS web config",            "HIGH"),
    ("/server-status",           "Apache server status",      "HIGH"),
    ("/server-info",             "Apache server info",        "HIGH"),

    # Medium — backup files, logs, sensitive data
    ("/backup.zip",              "Backup archive",            "MEDIUM"),
    ("/backup.tar.gz",           "Backup archive",            "MEDIUM"),
    ("/backup.sql",              "Database backup",           "MEDIUM"),
    ("/db.sql",                  "Database dump",             "MEDIUM"),
    ("/dump.sql",                "Database dump",             "MEDIUM"),
    ("/error.log",               "Error log file",            "MEDIUM"),
    ("/access.log",              "Access log file",           "MEDIUM"),
    ("/debug.log",               "Debug log file",            "MEDIUM"),
    ("/.htpasswd",               "Password file",             "MEDIUM"),
    ("/.htaccess",               "Apache htaccess",           "MEDIUM"),
    ("/crossdomain.xml",         "Flash crossdomain policy",  "MEDIUM"),

    # Low — information disclosure
    ("/robots.txt",              "Robots exclusion file",     "LOW"),
    ("/sitemap.xml",             "Sitemap file",              "LOW"),
    ("/security.txt",            "Security contact file",     "LOW"),
    ("/.well-known/security.txt","Security contact file",     "LOW"),
    ("/CHANGELOG.md",            "Changelog disclosure",      "LOW"),
    ("/CHANGELOG.txt",           "Changelog disclosure",      "LOW"),
    ("/README.md",               "README disclosure",         "LOW"),
    ("/LICENSE",                 "License disclosure",        "LOW"),
    ("/composer.json",           "PHP dependencies list",     "LOW"),
    ("/package.json",            "Node dependencies list",    "LOW"),
]

# ── Security headers to check ─────────────────────────────────────────────────
# Each entry: (header_name, description, severity_if_missing)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "HSTS — forces HTTPS connections",
        "HIGH",
    ),
    (
        "Content-Security-Policy",
        "CSP — prevents XSS and injection attacks",
        "HIGH",
    ),
    (
        "X-Frame-Options",
        "Prevents clickjacking attacks",
        "MEDIUM",
    ),
    (
        "X-Content-Type-Options",
        "Prevents MIME type sniffing",
        "MEDIUM",
    ),
    (
        "Referrer-Policy",
        "Controls referrer information leakage",
        "LOW",
    ),
    (
        "Permissions-Policy",
        "Controls browser feature access",
        "LOW",
    ),
]

# Headers that SHOULD NOT be present (information disclosure)
LEAKY_HEADERS = [
    ("Server",          "Reveals web server software and version", "LOW"),
    ("X-Powered-By",    "Reveals backend technology",             "LOW"),
    ("X-AspNet-Version","Reveals ASP.NET version",               "MEDIUM"),
    ("X-AspNetMvc-Version", "Reveals ASP.NET MVC version",       "MEDIUM"),
]

# ── TLS checks ────────────────────────────────────────────────────────────────
TLS_PORT             = 443
TLS_EXPIRY_WARNING   = 30   # warn if cert expires within this many days
TLS_EXPIRY_CRITICAL  = 7    # critical if expires within this many days

# ── Directory listing ─────────────────────────────────────────────────────────
# Signatures that indicate directory listing is enabled
DIRECTORY_LISTING_SIGNATURES = [
    "Index of /",
    "Directory listing for",
    "Parent Directory",
    "[To Parent Directory]",
]

# Common directories to probe for listing
DIRECTORY_PATHS = [
    "/",
    "/images/",
    "/uploads/",
    "/files/",
    "/backup/",
    "/assets/",
    "/static/",
    "/media/",
    "/data/",
    "/logs/",
    "/tmp/",
    "/temp/",
]

# ── Risk scoring ──────────────────────────────────────────────────────────────
SEVERITY_SCORES = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    7,
    "LOW":       2,
}

RISK_LEVELS = [
    (0,  "CLEAN"),
    (10, "LOW"),
    (30, "MEDIUM"),
    (60, "HIGH"),
    (999999, "CRITICAL"),
]
