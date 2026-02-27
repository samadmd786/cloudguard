"""
Organisational risk profiler.
Reads all stored findings from ChromaDB and produces a risk score,
severity breakdown, top recurring issues, and trend direction.
"""
import json
from datetime import datetime, timezone
from memory_store import get_all
from logger import get_logger

log = get_logger(__name__)

# Severity weights for risk score calculation
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}

# Max possible score for normalisation (assumes 50 critical findings = 500 pts -> 100)
MAX_SCORE_BASELINE = 500


def compute_risk_score(findings: list[dict]) -> int:
    """
    Score 0-100 based on weighted finding count.
    CRITICAL contributes 10x more than LOW.
    """
    if not findings:
        return 0
    raw = sum(SEV_WEIGHT.get(f.get("severity", "LOW"), 1) for f in findings)
    score = min(int((raw / MAX_SCORE_BASELINE) * 100), 100)
    return score


def get_profile() -> dict:
    """
    Compute and return the full org risk profile from stored findings.
    Returns a dict with: score, label, breakdown, top_issues, trend_hint, total.
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
