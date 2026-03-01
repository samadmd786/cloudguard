"""
AWS Security Hub Connector.

Manages interactions with the AWS Security Hub and STS APIs to verify
credentials, fetch active findings, and aggregate security summaries.
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from logger import get_logger

log = get_logger(__name__)


def get_client(key_id: str, secret: str, region: str = "us-east-1"):
    """
    Build a Security Hub boto3 client from explicit credentials.

    Args:
        key_id (str): AWS Access Key ID.
        secret (str): AWS Secret Access Key.
        region (str, optional): AWS region. Defaults to "us-east-1".

    Returns:
        boto3.client: A configured Security Hub client.
    """
    return boto3.client(
        "securityhub",
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )


def verify_aws_connection(key_id: str, secret: str, region: str = "us-east-1") -> dict:
    """
    Verify AWS credentials and Security Hub access.

    This function attempts to call `describe_hub` to ensure Security Hub
    is enabled in the specified region, and uses STS to fetch the account ID.

    Args:
        key_id (str): AWS Access Key ID.
        secret (str): AWS Secret Access Key.
        region (str, optional): AWS region to test against. Defaults to "us-east-1".

    Returns:
        dict: A dictionary containing:
            - 'ok' (bool): True if connection and access are successful.
            - 'account_id' (str, optional): The AWS Account ID if successful.
            - 'region' (str, optional): The verified region if successful.
            - 'error' (str, optional): Error message if 'ok' is False.
    """
    try:
        client = get_client(key_id, secret, region)
        client.describe_hub()
        sts = boto3.client("sts", aws_access_key_id=key_id, aws_secret_access_key=secret, region_name=region)
        account_id = sts.get_caller_identity().get("Account", "unknown")
        log.info(f"AWS connection OK | account={account_id} region={region}")
        return {"ok": True, "account_id": account_id, "region": region}
    except NoCredentialsError:
        return {"ok": False, "error": "Invalid or missing AWS credentials."}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidClientTokenId", "AuthFailure"):
            return {"ok": False, "error": "Invalid AWS credentials."}
        if code == "InvalidAccessException":
            return {"ok": False, "error": "Security Hub is not enabled in this region."}
        return {"ok": False, "error": f"AWS error: {e.response['Error']['Message']}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_findings(key_id: str, secret: str, severity_filter: list = None,
                 max_results: int = 50, region: str = "us-east-1") -> list[dict]:
    """
    Pull active findings from Security Hub.

    Args:
        key_id (str): AWS Access Key ID.
        secret (str): AWS Secret Access Key.
        severity_filter (list, optional): List of severity labels (e.g., ["HIGH", "CRITICAL"])
            to filter the results. If None, all severities are returned. Defaults to None.
        max_results (int, optional): Maximum number of findings to retrieve. Defaults to 50.
        region (str, optional): AWS region to pull from. Defaults to "us-east-1".

    Returns:
        list[dict]: A list of finding dictionaries retrieved from Security Hub.
    """
    try:
        client = get_client(key_id, secret, region)
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }
        if severity_filter:
            filters["SeverityLabel"] = [
                {"Value": sev, "Comparison": "EQUALS"} for sev in severity_filter
            ]

        # Use paginator to efficiently fetch findings across multiple API calls if needed
        findings = []
        paginator = client.get_paginator("get_findings")
        for page in paginator.paginate(
            Filters=filters,
            PaginationConfig={"MaxItems": max_results, "PageSize": min(max_results, 100)},
        ):
            findings.extend(page.get("Findings", []))
            if len(findings) >= max_results:
                break

        log.info(f"Fetched {len(findings)} findings | account session")
        return findings

    except NoCredentialsError:
        log.error("Missing credentials when fetching findings")
        return []
    except ClientError as e:
        log.error(f"ClientError fetching findings: {e.response['Error']['Message']}")
        return []
    except Exception as e:
        log.error(f"Unexpected error fetching findings: {e}")
        return []


def get_summary(findings: list[dict]) -> dict:
    """
    Return finding counts grouped by severity for the dashboard header.

    Calculates an aggregate count across all severities, including INFORMATIONAL items,
    based on the provided list of findings.

    Args:
        findings (list[dict]): A list of findings to summarize.

    Returns:
        dict: A dictionary mapping severity labels to their respective counts,
              plus a 'total' key for the overall sum.
    """
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "total": 0}
    for f in findings:
        sev = f.get("Severity", {}).get("Label", "")
        if sev in summary:
            summary[sev] += 1
            summary["total"] += 1
    return summary
