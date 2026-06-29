"""
run.py — PyShield Web Security Scanner
Entry point. Runs the full scan pipeline.

Usage:
    python run.py <target_url>

Examples:
    python run.py http://testphp.vulnweb.com
    python run.py https://example.com
    python run.py http://127.0.0.1:8080

Pipeline:
    1. Discovery     → find endpoints, detect technologies
    2. Exposed files → check sensitive paths
    3. Headers       → check security headers
    4. TLS           → check certificate validity
    5. Directory     → check for directory listing
    6. Risk engine   → score all findings
    7. Report        → write JSON + print summary
"""

import logging
import sys
import urllib.parse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("webscanner.run")

from http_client import HTTPClient
import discovery
from checks import exposed_files, headers, tls, directory
import risk_engine
import reporter


def run(target: str) -> dict:
    """Run full scan pipeline against target URL."""

    logger.info("=" * 60)
    logger.info("  PyShield Web Security Scanner")
    logger.info("  Target: %s", target)
    logger.info("=" * 60)

    # Build HTTP client — shared across all checks
    client = HTTPClient(target)

    # Extract hostname for TLS check
    parsed   = urllib.parse.urlparse(client.base_url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    all_findings = []

    # ── Step 1: Discovery ─────────────────────────────────────────────────────
    logger.info("[1/5] Running discovery...")
    disc = discovery.run(client)

    # ── Step 2: Exposed files ─────────────────────────────────────────────────
    logger.info("[2/5] Checking exposed files...")
    all_findings.extend(exposed_files.run(client))

    # ── Step 3: Security headers ──────────────────────────────────────────────
    logger.info("[3/5] Checking security headers...")
    all_findings.extend(headers.run(client))

    # ── Step 4: TLS certificate ───────────────────────────────────────────────
    if is_https and hostname:
        logger.info("[4/5] Checking TLS certificate...")
        all_findings.extend(tls.run(hostname))
    else:
        logger.info("[4/5] Skipping TLS check (target is HTTP not HTTPS)")
        if hostname:
            # Still flag that HTTPS is not used at all
            all_findings.append({
                "check":       "no_https",
                "description": "Site does not use HTTPS",
                "severity":    "HIGH",
                "evidence":    f"Target URL uses HTTP: {client.base_url}",
                "recommendation": (
                    "Enable HTTPS using a TLS certificate. "
                    "Let's Encrypt provides free certificates."
                ),
            })

    # ── Step 5: Directory listing ─────────────────────────────────────────────
    logger.info("[5/5] Checking directory listing...")
    all_findings.extend(directory.run(client))

    # ── Score and report ──────────────────────────────────────────────────────
    report = risk_engine.assess(client.base_url, all_findings, disc)
    reporter.write(report)
    reporter.print_summary(report)

    client.close()
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <target_url>")
        print("Examples:")
        print("  python run.py http://testphp.vulnweb.com")
        print("  python run.py https://example.com")
        sys.exit(1)

    run(sys.argv[1])
