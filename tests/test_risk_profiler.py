import pytest
from unittest.mock import patch
import risk_profiler

def test_compute_risk_score_empty():
    """Test the risk score computation for an empty findings list."""
    assert risk_profiler.compute_risk_score([]) == 0

def test_compute_risk_score_weighted():
    """Test the risk score computation weighs severities correctly."""
    findings = [
        {"severity": "CRITICAL"},  # +10
        {"severity": "CRITICAL"},  # +10
        {"severity": "HIGH"},      # +6
        {"severity": "MEDIUM"},    # +3
        {"severity": "LOW"},       # +1
        {"severity": "INFORMATIONAL"} # +1 (fallback)
    ]
    # Total raw score = 31.
    # Formula: min(int((31 / 500) * 100), 100) = 6
    score = risk_profiler.compute_risk_score(findings)
    assert score == 6

def test_compute_risk_score_caps_out():
    """Test the risk score computation caps at a maximum of 100."""
    findings = [{"severity": "CRITICAL"} for _ in range(100)]
    # raw score = 1000. 1000/500 * 100 = 200 -> capped at 100.
    score = risk_profiler.compute_risk_score(findings)
    assert score == 100

@patch("risk_profiler.get_all")
def test_get_profile_no_data(mock_get_all):
    """Test generating a risk profile when there are no findings in memory."""
    mock_get_all.return_value = []
    profile = risk_profiler.get_profile()
    
    assert profile["score"] == 0
    assert profile["total"] == 0
    assert profile["label"] == "No Data"
    assert "No Data" not in profile["trend_hint"] # just ensuring trend hint exists

@patch("risk_profiler.get_all")
def test_get_profile_with_data(mock_get_all):
    """Test generating a populated organizational risk profile."""
    # Provide enough CRITICALs to trip the "Critical Risk" label (score >= 70)
    # We need roughly 350 raw score -> 35 CRITICALs.
    findings = [{"severity": "CRITICAL", "title": "Bad S3 Bucket"} for _ in range(40)]
    
    # Add a few other severity findings
    findings.extend([
        {"severity": "HIGH", "title": "Open Port"},
        {"severity": "HIGH", "title": "Open Port"},
        {"severity": "MEDIUM", "title": "MFA Off"}
    ])
    
    mock_get_all.return_value = findings
    
    profile = risk_profiler.get_profile()
    
    assert profile["total"] == 43
    assert profile["label"] == "🔴 Critical Risk"
    assert profile["score"] >= 70
    
    # Check severity breakdown
    assert profile["breakdown"]["CRITICAL"] == 40
    assert profile["breakdown"]["HIGH"] == 2
    assert profile["breakdown"]["MEDIUM"] == 1
    
    # Check top issues counts
    assert profile["top_issues"][0]["title"] == "Bad S3 Bucket"
    assert profile["top_issues"][0]["count"] == 40
    
    # Check trend hint notices the cluster of critical issues
    assert "CRITICAL findings in the last 20 records" in profile["trend_hint"]
