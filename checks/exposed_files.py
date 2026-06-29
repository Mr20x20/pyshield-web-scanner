"""
checks/exposed_files.py — PyShield Web Security Scanner
Checks for sensitive files and directories left exposed on the web server.

This is the highest-value check in the scanner.
A single exposed .env file can contain:
  - Database credentials
  - API keys (AWS, Stripe, Sendgrid)
  - Secret keys for session signing
  - Third-party service tokens

Real world impact:
  In 2019, hundreds of thousands of Laravel apps had .env exposed.
  Attackers automated scraping of these files within hours of discovery.
"""

import logging

from config import EXPOSED_PATHS
from http_client import HTTPClient

logger = logging.getLogger("webscanner.checks.exposed_files")


# ── Finding structure ─────────────────────────────────────────────────────────
def _make_finding(path: str, description: str, severity: str,
                  status_code: int, evidence: str = "") -> dict:
    return {
        "check":       "exposed_files",
        "path":        path,
        "description": description,
        "severity":    severity,
        "status_code": status_code,
        "evidence":    evidence,
    }


# ── Public API ────────────────────────────────────────────────────────────────
def run(client: HTTPClient) -> list[dict]:
    findings = []
    logger.info("Checking %d sensitive paths...", len(EXPOSED_PATHS))

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check(args):
        i, path, description, severity = args
        logger.info("Checking [%d/%d]: %s", i, len(EXPOSED_PATHS), path)
        return _check_path(client, path, description, severity)

    items = [
        (i, path, desc, sev)
        for i, (path, desc, sev) in enumerate(EXPOSED_PATHS, 1)
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check, item): item for item in items}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                logger.warning(
                    "FOUND: %s [%s]",
                    result["path"], result["severity"]
                )

    logger.info("Exposed files check complete: %d finding(s)", len(findings))
    return findings


# ── Internal ──────────────────────────────────────────────────────────────────
def _check_path(client: HTTPClient, path: str,
                description: str, severity: str) -> dict | None:
    """
    Check a single path. Returns a finding dict or None.

    Logic:
      200 → exposed, extract evidence snippet
      401 → exists but auth-protected (lower severity)
      403 → exists but forbidden (keep original severity for critical paths)
      404 / other → not found, no finding
    """
    response = client.get(path, follow_redirects=False)

    if not response.ok:
        # Network error — skip silently
        return None

    status = response.status_code

    if status == 200:
        evidence = _extract_evidence(path, response.body)
        return _make_finding(path, description, severity, status, evidence)

    elif status == 401:
        # Exists but requires authentication
        # Downgrade severity by one level — it's protected but present
        downgraded = _downgrade_severity(severity)
        return _make_finding(
            path, f"{description} (auth required)",
            downgraded, status,
            "Resource exists but requires authentication"
        )

    elif status == 403:
        # Server is hiding it but confirms it exists
        # Only flag CRITICAL and HIGH paths for 403 — not worth
        # reporting every 403 on LOW items
        if severity in ("CRITICAL", "HIGH"):
            return _make_finding(
                path, f"{description} (access forbidden)",
                "MEDIUM", status,
                "Resource exists but access is forbidden — "
                "directory/file confirmed present"
            )

    return None


def _extract_evidence(path: str, body: str) -> str:
    """
    Extract a short evidence snippet from the response body.
    Helps confirm the finding is real, not a soft 404.

    For .env files: show first non-empty line (may contain key names)
    For .git:       show the HEAD reference
    For others:     show first 100 chars
    """
    if not body:
        return ""

    body = body.strip()

    # .env file — show key names (not values) from first few lines
    if ".env" in path:
        lines = [l.strip() for l in body.split("\n") if l.strip()]
        # Extract only key names (before =), not values
        key_names = []
        for line in lines[:5]:
            if "=" in line and not line.startswith("#"):
                key = line.split("=")[0].strip()
                key_names.append(key)
        if key_names:
            return f"Keys found: {', '.join(key_names)}"

    # .git/HEAD — show the branch reference
    if ".git" in path:
        first_line = body.split("\n")[0].strip()
        return first_line[:100]

    # phpinfo — confirm it's real phpinfo output
    if "phpinfo" in path or "info.php" in path:
        if "PHP Version" in body or "phpinfo()" in body:
            # Extract PHP version
            import re
            match = re.search(r"PHP Version\s*</td><td[^>]*>([\d.]+)", body)
            if match:
                return f"PHP Version: {match.group(1)}"
            return "phpinfo() page confirmed"

    # Default — first 120 chars
    return body[:120].replace("\n", " ").replace("\r", "")


def _downgrade_severity(severity: str) -> str:
    """Drop severity by one level."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    idx   = order.index(severity) if severity in order else 2
    return order[min(idx + 1, len(order) - 1)]
