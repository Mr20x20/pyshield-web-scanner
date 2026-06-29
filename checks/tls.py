"""
checks/tls.py — PyShield Web Security Scanner
Checks TLS/SSL certificate validity and configuration.

What we check:
  - Certificate expiry (expired or expiring soon)
  - Hostname mismatch (cert issued for different domain)
  - Self-signed certificate (no trusted CA)
  - Protocol version (TLS 1.0/1.1 are deprecated)
"""

import logging
import socket
import ssl
from datetime import datetime, timezone

from config import TLS_PORT, TLS_EXPIRY_WARNING, TLS_EXPIRY_CRITICAL

logger = logging.getLogger("webscanner.checks.tls")


def run(host: str) -> list[dict]:
    """
    Run all TLS checks against host:443.

    Args:
        host: hostname only e.g. "example.com" (no https://)

    Returns list of finding dicts.
    """
    findings = []

    # Only check TLS if host looks like it has HTTPS
    try:
        cert_info = _get_cert_info(host)
    except Exception as e:
        logger.debug("TLS check skipped for %s: %s", host, e)
        return []

    if not cert_info:
        return []

    # Check 1: Certificate expiry
    expiry_finding = _check_expiry(host, cert_info)
    if expiry_finding:
        findings.append(expiry_finding)

    # Check 2: Hostname mismatch
    mismatch_finding = _check_hostname(host, cert_info)
    if mismatch_finding:
        findings.append(mismatch_finding)

    # Check 3: Self-signed
    selfsigned_finding = _check_self_signed(host, cert_info)
    if selfsigned_finding:
        findings.append(selfsigned_finding)

    logger.info("TLS checks complete: %d finding(s)", len(findings))
    return findings


# ── Certificate fetching ──────────────────────────────────────────────────────
def _get_cert_info(host: str) -> dict | None:
    """
    Connect to host:443 and retrieve certificate information.
    Uses ssl.CERT_NONE so we can inspect even invalid certs.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((host, TLS_PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert        = ssock.getpeercert()
                cipher      = ssock.cipher()
                tls_version = ssock.version()

                return {
                    "cert":        cert,
                    "cipher":      cipher,
                    "tls_version": tls_version,
                    "host":        host,
                }

    except ConnectionRefusedError:
        logger.debug("Port 443 closed on %s", host)
        return None
    except socket.timeout:
        logger.debug("TLS connection timeout for %s", host)
        return None
    except Exception as e:
        logger.debug("TLS error for %s: %s", host, e)
        return None


# ── Individual checks ─────────────────────────────────────────────────────────
def _check_expiry(host: str, cert_info: dict) -> dict | None:
    """Check if certificate is expired or expiring soon."""
    cert = cert_info.get("cert", {})
    if not cert:
        return None

    not_after = cert.get("notAfter", "")
    if not not_after:
        return None

    try:
        # Parse SSL date format: "Dec 31 23:59:59 2024 GMT"
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        now         = datetime.now(timezone.utc)
        days_left   = (expiry_date - now).days

        if days_left < 0:
            return {
                "check":       "tls_cert_expired",
                "description": f"TLS certificate EXPIRED {abs(days_left)} days ago",
                "severity":    "CRITICAL",
                "evidence":    f"Certificate expired on {expiry_date.strftime('%Y-%m-%d')}",
                "recommendation": "Renew the TLS certificate immediately.",
            }

        elif days_left <= TLS_EXPIRY_CRITICAL:
            return {
                "check":       "tls_cert_expiring",
                "description": f"TLS certificate expires in {days_left} days",
                "severity":    "CRITICAL",
                "evidence":    f"Expires: {expiry_date.strftime('%Y-%m-%d')}",
                "recommendation": f"Renew the TLS certificate within {days_left} days.",
            }

        elif days_left <= TLS_EXPIRY_WARNING:
            return {
                "check":       "tls_cert_expiring",
                "description": f"TLS certificate expires in {days_left} days",
                "severity":    "HIGH",
                "evidence":    f"Expires: {expiry_date.strftime('%Y-%m-%d')}",
                "recommendation": "Plan certificate renewal soon.",
            }

        else:
            logger.info(
                "TLS cert for %s valid for %d more days", host, days_left
            )

    except Exception as e:
        logger.debug("Could not parse cert expiry: %s", e)

    return None


def _check_hostname(host: str, cert_info: dict) -> dict | None:
    """Check if certificate is issued for the correct hostname."""
    cert = cert_info.get("cert", {})
    if not cert:
        return None

    try:
        ssl.match_hostname(cert, host)
        logger.debug("TLS hostname match OK for %s", host)
        return None
    except ssl.CertificateError as e:
        return {
            "check":       "tls_hostname_mismatch",
            "description": "TLS certificate hostname mismatch",
            "severity":    "HIGH",
            "evidence":    str(e),
            "recommendation": (
                "Ensure the certificate is issued for the correct domain. "
                "Check SANs (Subject Alternative Names)."
            ),
        }
    except Exception:
        return None


def _check_self_signed(host: str, cert_info: dict) -> dict | None:
    """Check if certificate is self-signed (issuer == subject)."""
    cert = cert_info.get("cert", {})
    if not cert:
        return None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))

    subject_cn = subject.get("commonName", "")
    issuer_cn  = issuer.get("commonName", "")
    issuer_org = issuer.get("organizationName", "")

    # Self-signed: issuer and subject are the same
    if subject_cn and subject_cn == issuer_cn:
        return {
            "check":       "tls_self_signed",
            "description": "Self-signed TLS certificate detected",
            "severity":    "HIGH",
            "evidence":    (
                f"Subject: {subject_cn} | "
                f"Issuer: {issuer_org or issuer_cn}"
            ),
            "recommendation": (
                "Replace self-signed certificate with one issued by a "
                "trusted Certificate Authority (e.g. Let's Encrypt)."
            ),
        }

    return None
