"""
reporter.py — PyShield Web Security Scanner
Writes the final JSON report to disk.
"""

import json
import logging

from config import REPORT_FILE

logger = logging.getLogger("webscanner.reporter")


def write(report: dict) -> None:
    """Write the assessment report to JSON file."""
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        logger.info("Report saved to %s", REPORT_FILE)
    except Exception as e:
        logger.error("Failed to write report: %s", e)


def print_summary(report: dict) -> None:
    """Print a clean terminal summary."""
    counts = report.get("counts", {})
    print("\n" + "=" * 60)
    print("  PyShield Web Security Scanner — Results")
    print("=" * 60)
    print(f"  Target     : {report['target']}")
    print(f"  Timestamp  : {report['timestamp']}")
    print(f"  Risk Score : {report['total_score']}")
    print(f"  Risk Level : {report['risk_level']}")
    print("-" * 60)
    print(
        f"  Findings   : {len(report.get('findings', []))} total | "
        f"CRITICAL:{counts.get('CRITICAL',0)} "
        f"HIGH:{counts.get('HIGH',0)} "
        f"MEDIUM:{counts.get('MEDIUM',0)} "
        f"LOW:{counts.get('LOW',0)}"
    )
    print("-" * 60)

    # Discovery info
    disc = report.get("discovery", {})
    if disc.get("technologies"):
        print(f"  Tech Stack : {', '.join(disc['technologies'])}")
    if disc.get("server"):
        print(f"  Server     : {disc['server']}")
    if disc.get("title"):
        print(f"  Page Title : {disc['title']}")
    print("-" * 60)

    # Summary lines
    print("  SUMMARY:")
    for line in report.get("summary", []):
        print(f"  {line}")
    print("-" * 60)

    # Top findings
    print("  FINDINGS:")
    for f in report.get("findings", []):
        sev  = f.get("severity", "?")
        desc = f.get("description", "")
        path = f.get("path", f.get("header", ""))
        print(f"  [{sev:8}] {desc[:55]:55} {path}")

    print("=" * 60)
    print(f"  Full report: {REPORT_FILE}\n")
