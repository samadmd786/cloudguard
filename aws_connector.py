import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from logger import get_logger

log = get_logger(__name__)


def get_client(region: str = None):
    """Build a Security Hub boto3 client from environment credentials."""
    return boto3.client(
        "securityhub",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name=region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def test_connection(region: str = None) -> dict:
    """
    Verify AWS credentials and Security Hub access.
    Returns {"ok": True, "account_id": "...", "region": "..."} on success
    or {"ok": False, "error": "..."} on failure.
    """
    try:
        client = get_client(region)
        hub = client.describe_hub()
        sts = boto3.client(
            "sts",
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            region_name=region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "unknown")
        log.info(f"AWS connection OK | account={account_id} region={client.meta.region_name}")
        return {"ok": True, "account_id": account_id, "region": client.meta.region_name}
    except NoCredentialsError:
        return {"ok": False, "error": "AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidClientTokenId", "AuthFailure"):
            return {"ok": False, "error": "Invalid AWS credentials."}
        if code == "InvalidAccessException":
            return {"ok": False, "error": "Security Hub is not enabled in this region."}
        return {"ok": False, "error": f"AWS error: {e.response['Error']['Message']}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_findings(severity_filter: list = None, max_results: int = 50, region: str = None) -> list[dict]:
    """
    Pull active, failed findings from Security Hub.
    severity_filter: list of labels e.g. ["CRITICAL", "HIGH"]
    Returns a list of normalized finding dicts.
    """
    try:
        client = get_client(region)

        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        }
        if severity_filter:
            filters["SeverityLabel"] = [
                {"Value": sev, "Comparison": "EQUALS"} for sev in severity_filter
            ]

        findings = []
        paginator = client.get_paginator("get_findings")
        for page in paginator.paginate(
            Filters=filters,
            PaginationConfig={"MaxItems": max_results, "PageSize": min(max_results, 100)},
        ):
            findings.extend(page.get("Findings", []))
            if len(findings) >= max_results:
                break

        log.info(f"Fetched {len(findings)} findings from Security Hub")
        return findings

    except NoCredentialsError:
        log.error("AWS credentials missing when fetching findings")
        return []
    except ClientError as e:
        log.error(f"ClientError fetching findings: {e.response['Error']['Message']}")
        return []
    except Exception as e:
        log.error(f"Unexpected error fetching findings: {e}")
        return []


def get_summary(region: str = None) -> dict:
    """Return finding counts grouped by severity for the dashboard header."""
    all_findings = get_findings(max_results=200, region=region)
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
    for f in all_findings:
        sev = f.get("Severity", {}).get("Label", "")
        if sev in summary:
            summary[sev] += 1
            summary["total"] += 1
    return summary
