import pytest
from cloudguard.tools import lookup_cves, fetch_aws_remediation, check_compliance, execute_tool

def test_check_compliance_known_service():
    """Test compliance lookup for a known service (s3)."""
    res = check_compliance("public access", "s3")
    assert res["service"] == "s3"
    assert res["finding_type"] == "public access"
    assert len(res["controls"]) > 0
    # S3 should map to CIS 2.1.1, etc.
    frameworks = {c["framework"] for c in res["controls"]}
    assert "CIS" in frameworks
    assert "PCI DSS" in frameworks

def test_check_compliance_unknown_service():
    """Test compliance lookup for an unknown service falls back to default."""
    res = check_compliance("weird error", "unknown_service")
    assert len(res["controls"]) > 0
    ids = [c["control_id"] for c in res["controls"]]
    assert "1.1" in ids  # Default CIS control

def test_fetch_aws_remediation_known():
    """Test fetching AWS docs URL for a known Security Hub control prefix."""
    res = fetch_aws_remediation("S3.1")
    assert res["control_id"] == "S3.1"
    assert "s3-controls.html" in res["url"]
    assert res.get("error") is None

def test_fetch_aws_remediation_unknown(mocker):
    """Test fetching AWS docs URL for an unknown prefix caches and returns IAM default."""
    # Mock requests.get so we don't actually hit the network during unit tests
    mock_get = mocker.patch("requests.get")
    mock_resp = mocker.Mock()
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp

    res = fetch_aws_remediation("UNKNOWN_SERVICE.1")
    assert res["control_id"] == "UNKNOWN_SERVICE.1"
    assert "iam-controls.html" in res["url"]

def test_execute_tool_valid():
    """Test the execute_tool dispatcher for a valid tool."""
    # check_compliance is safe to test as it has no network calls
    res_str = execute_tool("check_compliance", {"finding_type": "test", "service": "ec2"})
    assert '"service": "ec2"' in res_str

def test_execute_tool_invalid():
    """Test the execute_tool dispatcher returns an error for unknown tools."""
    res_str = execute_tool("fake_tool", {})
    assert "Unknown tool" in res_str
