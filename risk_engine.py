"""
risk_engine.py — PyShield Web Security Scanner
Scores all findings and produces a final risk assessment.
"""

import logging
from datetime import datetime

from config import SEVERITY_SCORES, RISK_LEVELS

logger = logging.getLogger("webscanner.risk_engine")


def assess(target: str, all_findings: list[dict],
           discovery: dict) -> dict:
    """
    Score all findings and build the final report structure.

    Args:
        target      : scanned URL
        all_findings: combined findings from all check modules
        discovery   : output from discovery.run()

    Returns full assessment dict.
    """
    total_score = 0
    counts      = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in all_findings:
        severity     = finding.get("severity", "LOW")
        score        = SEVERITY_SCORES.get(severity, 0)
        total_score += score
        if severity in counts:
            counts[severity] += 1

    risk_level = _get_risk_level(total_score)
    summary    = _build_summary(target, total_score, risk_level,
                                all_findings, counts, discovery)

    # Sort findings: CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(
        key=lambda x: severity_order.get(x.get("severity", "LOW"), 3)
    )

    report = {
        "target":      target,
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_score": total_score,
        "risk_level":  risk_level,
        "summary":     summary,
        "counts":      counts,
        "findings":    all_findings,
        "discovery":   discovery,
    }

    logger.info(
        "Assessment: score=%d level=%s findings=%d "
        "(C:%d H:%d M:%d L:%d)",
        total_score, risk_level, len(all_findings),
        counts["CRITICAL"], counts["HIGH"],
        counts["MEDIUM"], counts["LOW"],
    )
    return report


def _get_risk_level(score: int) -> str:
    for threshold, level in RISK_LEVELS:
        if score <= threshold:
            return level
    return "CRITICAL"


def _build_summary(target: str, score: int, level: str,
                   findings: list[dict], counts: dict,
                   discovery: dict) -> list[str]:
    summary = []

    summary.append(
        f"• Target: {target} | Score: {score} | Level: {level}"
    )
    summary.append(
        f"• {len(findings)} finding(s): "
        f"{counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH, "
        f"{counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW"
    )

    techs = discovery.get("technologies", [])
    if techs:
        summary.append(f"• Technologies detected: {', '.join(techs)}")

    if counts["CRITICAL"] > 0:
        crit = [f for f in findings if f.get("severity") == "CRITICAL"]
        for f in crit[:3]:
            desc = f.get("description", "")
            summary.append(f"• 🔥 CRITICAL: {desc}")

    robots = discovery.get("robots_paths", [])
    if robots:
        summary.append(
            f"• robots.txt revealed {len(robots)} hidden path(s): "
            f"{', '.join(robots[:3])}"
        )

    return summary
