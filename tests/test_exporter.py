import pytest
from exporter import to_markdown
import json

def test_to_markdown_success():
    """Test generating a markdown report from a standard finding and result."""
    finding = {
        "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/uuid",
        "Title": "S3 bucket public access is not blocked",
        "Severity": {"Label": "CRITICAL"},
        "Resources": [{"Id": "arn:aws:s3:::my-public-bucket"}]
    }

    result = {
        "plain_english": "The S3 bucket is public.",
        "why_it_matters": "Anyone can read it.",
        "business_impact": {
            "data_risk": "High",
            "financial_risk": "High",
            "compliance_risk": "High"
        },
        "fix_steps": [
            {
                "step": "Go to AWS Console",
                "cli_command": ""
            },
            {
                "step": "Run AWS CLI",
                "cli_command": "aws s3api put-public-access-block --bucket my-public-bucket"
            }
        ],
        "compliance_frameworks": ["CIS 2.1.5", "PCI DSS 1.3.6"],
        "priority": "Immediate",
        "tldr": "Stop public bucket now."
    }

    md = to_markdown(finding, result)
    
    # Assert headers and key values are present
    assert "# CloudGuard AI — Security Finding Report" in md
    assert "## S3 bucket public access is not blocked" in md
    assert "| **Severity** | CRITICAL |" in md
    assert "| **Priority** | Immediate |" in md
    assert "`arn:aws:s3:::my-public-bucket`" in md
    
    # Assert sections exist
    assert "## TL;DR" in md
    assert "> Stop public bucket now." in md
    assert "## What Happened" in md
    assert "The S3 bucket is public." in md
    assert "## Why It Matters" in md
    assert "Anyone can read it." in md
    
    # Assert remediation steps and CLI exist
    assert "## Remediation Steps" in md
    assert "### Step 1: Go to AWS Console" in md
    assert "### Step 2: Run AWS CLI" in md
    assert "```bash\naws s3api put-public-access-block --bucket my-public-bucket\n```" in md

    # Assert compliance
    assert "## Compliance Frameworks" in md
    assert "`CIS 2.1.5`, `PCI DSS 1.3.6`" in md

def test_to_markdown_missing_fields():
    """Test markdown generation when finding or result is missing fields."""
    finding = {
        "Title": "Partial finding"
    }
    result = {
        "tldr": "Partial result"
    }

    md = to_markdown(finding, result)
    assert "## Partial finding" in md
    assert "| **Severity** | UNKNOWN |" in md
    assert "| **Resource** | `—` |" in md
    assert "| **Finding ID** | `—` |" in md
    assert "## Remediation Steps" not in md  # Should completely skip if empty
    assert "## Compliance Frameworks" not in md # Should completely skip if empty
