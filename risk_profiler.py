"""
Organizational Risk Profiler.

This module reads all stored findings from the local ChromaDB vector store
(populated via `memory_store.py`) and calculates an aggregate risk score,
severity breakdown, top recurring issues, and trend direction for the
'Risk Profile' dashboard tab.
"""
import json
from datetime import datetime, timezone
from memory_store import get_all
from logger import get_logger

log = get_logger(__name__)

# Severity weights for risk score calculation
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}


def compute_risk_score(findings: list[dict]) -> int:
    """
    Calculate an aggregate risk score (0-100) based on average severity.

    Uses a weighted-average approach: the base score reflects the average
    severity of all findings (all-CRITICAL = 100, all-LOW = 10). A small
    volume boost (+1 per extra finding, capped at +20) ensures that having
    more unresolved findings pushes the score higher.

    Args:
        findings (list[dict]): A list of finding dictionaries retrieved from memory.

    Returns:
        int: The calculated risk score, capped at 100.
    """
    if not findings:
        return 0
    total = len(findings)
    raw = sum(SEV_WEIGHT.get(f.get("severity", "LOW"), 1) for f in findings)

    # Average severity weight (0-10) normalised to 0-100
    base_score = int((raw / total / 10) * 100)

    # More unresolved findings = slightly higher risk, capped at +20
    volume_boost = min(total - 1, 20)

    return min(100, base_score + volume_boost)


def get_profile() -> dict:
    """
    Compute and return the full organizational risk profile.

    Aggregates all stored findings to generate insights for the UI.

    Returns:
        dict: A dictionary containing:
            - 'score' (int): The 0-100 risk score.
            - 'label' (str): The human-readable risk classification (e.g., 'High Risk').
            - 'breakdown' (dict): Counts by severity level.
            - 'top_issues' (list[dict]): The top 5 most frequent finding titles.
            - 'trend_hint' (str): A static analysis sentence predicting risk direction.
            - 'total' (int): Total number of analyzed findings in storage.
    """
    findings = get_all(limit=500)
    total = len(findings)
    log.info(f"Risk profiler: {total} findings in store")

    if total == 0:
        return {
            "score": 0, "label": "No Data",
            "breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_issues": [], "trend_hint": "Analyse some findings to build your risk profile.",
            "total": 0,
        }

    # Severity breakdown
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    title_counts: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in breakdown:
            breakdown[sev] += 1
        title = f.get("title", "Unknown")
        title_counts[title] = title_counts.get(title, 0) + 1

    score = compute_risk_score(findings)

    if score >= 70:
        label = "🔴 Critical Risk"
    elif score >= 40:
        label = "🟠 High Risk"
    elif score >= 20:
        label = "🟡 Moderate Risk"
    else:
        label = "🟢 Low Risk"

    # Top 5 recurring issues
    top_issues = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Simple trend hint based on recency of CRITICAL findings
    recent_critical = sum(
        1 for f in findings[-20:] if f.get("severity") == "CRITICAL"
    )
    if recent_critical >= 3:
        trend_hint = f"⚠️ {recent_critical} CRITICAL findings in the last 20 records — risk is increasing."
    elif breakdown["CRITICAL"] == 0:
        trend_hint = "✅ No CRITICAL findings stored — maintain regular scanning."
    else:
        trend_hint = "ℹ️ Risk appears stable. Keep remediating HIGH findings."

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        "top_issues": [{"title": t, "count": c} for t, c in top_issues],
        "trend_hint": trend_hint,
        "total": total,
    }
