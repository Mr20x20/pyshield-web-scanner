"""
checks/headers.py — PyShield Web Security Scanner
Checks HTTP security headers on the target's home page.

Two types of checks:
  1. Missing security headers  → should be present but aren't
  2. Leaky informational headers → should NOT be present but are

Why headers matter:
  Content-Security-Policy missing → XSS attacks have no browser-level defense
  Strict-Transport-Security missing → attackers can downgrade HTTPS to HTTP
  Server: nginx/1.18.0 present → tells attacker exactly what CVEs to look for
"""

import logging

from config import SECURITY_HEADERS, LEAKY_HEADERS
from http_client import HTTPClient

logger = logging.getLogger("webscanner.checks.headers")


def run(client: HTTPClient) -> list[dict]:
    """
    Check security headers on the target root URL.
    Returns list of finding dicts.
    """
    findings = []

    # Fetch root page headers — HEAD request is enough
    response = client.get_headers_only("/")

    if not response.ok:
        logger.warning("Could not fetch headers: %s", response.error)
        return []

    logger.info(
        "Checking headers on %s (status %d)",
        response.url, response.status_code
    )

    # ── Check 1: Missing security headers ────────────────────────────────────
    for header_name, description, severity in SECURITY_HEADERS:
        value = response.header(header_name)

        if not value:
            findings.append({
                "check":       "missing_security_header",
                "header":      header_name,
                "description": f"Missing: {description}",
                "severity":    severity,
                "evidence":    f"Header '{header_name}' not present in response",
                "recommendation": _get_recommendation(header_name),
            })
            logger.warning("MISSING header: %s [%s]", header_name, severity)
        else:
            # Header present — check for weak values
            weakness = _check_header_value(header_name, value)
            if weakness:
                findings.append({
                    "check":       "weak_security_header",
                    "header":      header_name,
                    "description": f"Weak {header_name}: {weakness}",
                    "severity":    "MEDIUM",
                    "evidence":    f"{header_name}: {value}",
                    "recommendation": _get_recommendation(header_name),
                })
                logger.warning(
                    "WEAK header: %s = %s (%s)",
                    header_name, value[:60], weakness
                )
            else:
                logger.debug("OK header: %s", header_name)

    # ── Check 2: Leaky informational headers ──────────────────────────────────
    for header_name, description, severity in LEAKY_HEADERS:
        value = response.header(header_name)

        if value:
            findings.append({
                "check":       "leaky_header",
                "header":      header_name,
                "description": f"Information disclosure: {description}",
                "severity":    severity,
                "evidence":    f"{header_name}: {value}",
                "recommendation": (
                    f"Remove or obscure the '{header_name}' header "
                    f"to prevent technology fingerprinting."
                ),
            })
            logger.warning(
                "LEAKY header: %s: %s [%s]",
                header_name, value, severity
            )

    logger.info("Header checks complete: %d finding(s)", len(findings))
    return findings


# ── Header value validators ───────────────────────────────────────────────────
def _check_header_value(header: str, value: str) -> str:
    """
    Check if a present header has a weak or misconfigured value.
    Returns a description of the weakness, or empty string if OK.
    """
    header_lower = header.lower()
    value_lower  = value.lower()

    if header_lower == "strict-transport-security":
        # HSTS must have max-age — the longer the better
        # Less than 6 months (15768000s) is considered weak
        import re
        match = re.search(r"max-age=(\d+)", value_lower)
        if not match:
            return "max-age directive missing"
        max_age = int(match.group(1))
        if max_age < 15768000:
            return f"max-age={max_age} is too short (recommend ≥ 15768000)"

    elif header_lower == "content-security-policy":
        # CSP with 'unsafe-inline' or 'unsafe-eval' defeats the purpose
        if "unsafe-inline" in value_lower:
            return "'unsafe-inline' weakens CSP protection"
        if "unsafe-eval" in value_lower:
            return "'unsafe-eval' weakens CSP protection"
        if value_lower.strip() == "*":
            return "Wildcard CSP provides no protection"

    elif header_lower == "x-frame-options":
        # Must be DENY or SAMEORIGIN — ALLOWALL is insecure
        if "allow-from" in value_lower or "allowall" in value_lower:
            return "ALLOWALL provides no clickjacking protection"

    elif header_lower == "x-content-type-options":
        # Must be exactly 'nosniff'
        if value_lower.strip() != "nosniff":
            return f"Value should be 'nosniff', got '{value}'"

    return ""   # no weakness found


# ── Recommendations ───────────────────────────────────────────────────────────
def _get_recommendation(header: str) -> str:
    """Return a fix recommendation for each missing/weak header."""
    recs = {
        "Strict-Transport-Security": (
            "Add: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
        "Content-Security-Policy": (
            "Add a CSP header to restrict content sources. "
            "Start with: Content-Security-Policy: default-src 'self'"
        ),
        "X-Frame-Options": (
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing needed)"
        ),
        "X-Content-Type-Options": (
            "Add: X-Content-Type-Options: nosniff"
        ),
        "Referrer-Policy": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ),
        "Permissions-Policy": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
    }
    return recs.get(header, f"Research and implement the {header} header.")
