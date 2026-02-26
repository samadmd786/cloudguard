"""
Tests for analyzer.py

Run with:
    ./venv/bin/python3 -m pytest tests/test_analyzer.py -v

Integration tests (LIVE=1) make real Claude API calls and cost ~$0.015 total.
Unit tests mock the API and cost nothing.
"""
import json
import os
import pytest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from analyzer import analyze_finding, SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FINDINGS_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_findings")

def load_finding(name: str) -> dict:
    with open(os.path.join(FINDINGS_DIR, name)) as f:
        return json.load(f)

VALID_RESPONSE = {
    "plain_english": "The S3 bucket my-company-data-backup-prod is publicly readable.",
    "why_it_matters": "Anyone on the internet can read your data.",
    "business_impact": {
        "data_risk": "Full data exposure.",
        "financial_risk": "GDPR fines up to 4% of revenue.",
        "compliance_risk": "Violates PCI DSS 1.3.6.",
    },
    "fix_steps": [
        {
            "step": "Enable Block Public Access on the bucket.",
            "cli_command": "aws s3api put-public-access-block --bucket my-company-data-backup-prod --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        },
        {
            "step": "Audit the bucket ACL and remove all public grants.",
            "cli_command": "aws s3api get-bucket-acl --bucket my-company-data-backup-prod",
        },
    ],
    "compliance_frameworks": ["CIS AWS 2.3", "PCI DSS 1.3.6", "NIST AC-3"],
    "priority": "Immediate",
    "tldr": "Your S3 bucket is publicly readable — fix it now.",
}


def make_mock_client(response_text: str):
    """Return a mock Anthropic client that returns the given text."""
    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text=response_text)]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_msg
    return mock_client


# ---------------------------------------------------------------------------
# Unit tests — no API calls, no cost
# ---------------------------------------------------------------------------

class TestAnalyzeFindingUnit:

    def test_returns_all_required_fields(self):
        """Happy path: valid finding + mocked Claude response returns all fields."""
        finding = load_finding("s3_public.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client(json.dumps(VALID_RESPONSE))):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        required = ["plain_english", "why_it_matters", "business_impact",
                    "fix_steps", "compliance_frameworks", "priority", "tldr"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_fix_steps_have_step_and_cli(self):
        """Each fix step must have 'step' and 'cli_command' keys."""
        finding = load_finding("ssh_open.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client(json.dumps(VALID_RESPONSE))):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        for step in result["fix_steps"]:
            assert "step" in step
            assert "cli_command" in step

    def test_priority_is_valid_value(self):
        """Priority must be one of the three allowed values."""
        finding = load_finding("root_keys.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client(json.dumps(VALID_RESPONSE))):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        assert result["priority"] in ("Immediate", "Soon", "Planned")

    def test_business_impact_has_three_keys(self):
        """business_impact must contain data_risk, financial_risk, compliance_risk."""
        finding = load_finding("mfa_disabled.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client(json.dumps(VALID_RESPONSE))):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        impact = result["business_impact"]
        assert "data_risk" in impact
        assert "financial_risk" in impact
        assert "compliance_risk" in impact

    def test_strips_markdown_fences(self):
        """Claude sometimes wraps JSON in ```json ... ``` — must be stripped."""
        fenced = f"```json\n{json.dumps(VALID_RESPONSE)}\n```"
        finding = load_finding("cloudtrail.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client(fenced)):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        assert "plain_english" in result
        assert "error" not in result

    def test_missing_api_key_raises_valueerror(self):
        """No API key in env and none passed → ValueError."""
        finding = load_finding("s3_public.json")
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY not set"):
                analyze_finding(finding, api_key=None)

    def test_invalid_json_from_claude_returns_error(self):
        """If Claude returns garbage text, result has 'error' key not a crash."""
        finding = load_finding("s3_public.json")
        with patch("analyzer.anthropic.Anthropic", return_value=make_mock_client("not valid json at all")):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        assert "error" in result
        assert "invalid JSON" in result["error"]

    def test_auth_error_returns_error_dict(self):
        """Bad API key → returns error dict, does not crash."""
        import anthropic as anthropic_lib
        finding = load_finding("s3_public.json")
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic_lib.AuthenticationError(
            message="Invalid API key", response=MagicMock(status_code=401), body={}
        )
        with patch("analyzer.anthropic.Anthropic", return_value=mock_client):
            result = analyze_finding(finding, api_key="sk-ant-bad-key")

        assert "error" in result
        assert "Invalid Anthropic API key" in result["error"]

    def test_rate_limit_returns_error_dict(self):
        """Rate limit hit → returns error dict, does not crash."""
        import anthropic as anthropic_lib
        finding = load_finding("s3_public.json")
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic_lib.RateLimitError(
            message="Rate limit", response=MagicMock(status_code=429), body={}
        )
        with patch("analyzer.anthropic.Anthropic", return_value=mock_client):
            result = analyze_finding(finding, api_key="sk-ant-fake-key")

        assert "error" in result
        assert "Rate limit" in result["error"]


# ---------------------------------------------------------------------------
# Integration tests — only run when LIVE=1 is set (makes real API calls)
# ---------------------------------------------------------------------------

LIVE = os.environ.get("LIVE") == "1"

@pytest.mark.skipif(not LIVE, reason="Set LIVE=1 to run integration tests (costs ~$0.015)")
class TestAnalyzeFindingIntegration:

    @pytest.mark.parametrize("filename,expected_priority", [
        ("s3_public.json",    "Immediate"),
        ("root_keys.json",    "Immediate"),
        ("ssh_open.json",     "Immediate"),
        ("mfa_disabled.json", "Immediate"),
        ("cloudtrail.json",   "Soon"),
    ])
    def test_all_findings_return_valid_response(self, filename, expected_priority):
        """Each sample finding returns a structured, parseable response from Claude."""
        finding = load_finding(filename)
        result = analyze_finding(finding)

        assert "error" not in result, f"Got error for {filename}: {result['error']}"
        assert result["priority"] in ("Immediate", "Soon", "Planned")
        assert len(result["fix_steps"]) >= 2
        assert len(result["tldr"]) > 10
        assert len(result["compliance_frameworks"]) >= 1
