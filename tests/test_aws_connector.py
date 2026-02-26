import pytest
import boto3
from pytest_mock import MockerFixture
from botocore.exceptions import ClientError, NoCredentialsError
from aws_connector import get_client, verify_aws_connection, get_findings, get_summary

def test_get_client(mocker: MockerFixture):
    mock_boto = mocker.patch("aws_connector.boto3.client")
    get_client("fake_key", "fake_secret", "us-west-2")
    mock_boto.assert_called_once_with(
        "securityhub",
        aws_access_key_id="fake_key",
        aws_secret_access_key="fake_secret",
        region_name="us-west-2"
    )

def test_verify_aws_connection_success(mocker: MockerFixture):
    mock_hub = mocker.MagicMock()
    mock_sts = mocker.MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    
    mock_get_client = mocker.patch("aws_connector.get_client", return_value=mock_hub)
    mock_boto_client = mocker.patch("aws_connector.boto3.client", return_value=mock_sts)

    result = verify_aws_connection("key", "secret", "us-east-1")

    assert result["ok"] is True
    assert result["account_id"] == "123456789012"
    assert result["region"] == "us-east-1"
    mock_hub.describe_hub.assert_called_once()
    mock_sts.get_caller_identity.assert_called_once()

def test_verify_aws_connection_no_credentials(mocker: MockerFixture):
    mock_get_client = mocker.patch("aws_connector.get_client", side_effect=NoCredentialsError)
    result = verify_aws_connection("key", "secret", "us-east-1")
    assert result["ok"] is False
    assert "Invalid or missing AWS credentials" in result["error"]

def test_verify_aws_connection_client_error(mocker: MockerFixture):
    error_response = {"Error": {"Code": "AuthFailure", "Message": "Invalid login"}}
    mock_get_client = mocker.patch("aws_connector.get_client", side_effect=ClientError(error_response, "DescribeHub"))
    result = verify_aws_connection("key", "secret", "us-east-1")
    assert result["ok"] is False
    assert result["error"] == "Invalid AWS credentials."

def test_get_findings_success(mocker: MockerFixture):
    mock_hub = mocker.MagicMock()
    mock_paginator = mocker.MagicMock()
    mock_hub.get_paginator.return_value = mock_paginator
    
    # Mocking single page of results
    mock_paginator.paginate.return_value = [{"Findings": [{"Id": "1", "Title": "Finding 1"}, {"Id": "2", "Title": "Finding 2"}]}]
    
    mocker.patch("aws_connector.get_client", return_value=mock_hub)
    
    findings = get_findings("key", "secret", severity_filter=["CRITICAL"], max_results=10, region="us-east-1")
    
    assert len(findings) == 2
    assert findings[0]["Id"] == "1"
    mock_hub.get_paginator.assert_called_once_with("get_findings")

def test_get_findings_handles_client_error(mocker: MockerFixture):
    error_response = {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}
    mocker.patch("aws_connector.get_client", side_effect=ClientError(error_response, "GetFindings"))
    findings = get_findings("key", "secret")
    assert findings == []

def test_get_summary(mocker: MockerFixture):
    mock_findings = [
        {"Severity": {"Label": "CRITICAL"}},
        {"Severity": {"Label": "CRITICAL"}},
        {"Severity": {"Label": "HIGH"}},
        {"Severity": {"Label": "LOW"}},
        {}, # Missing severity entirely
    ]
    mocker.patch("aws_connector.get_findings", return_value=mock_findings)
    
    summary = get_summary("key", "secret")
    
    assert summary["CRITICAL"] == 2
    assert summary["HIGH"] == 1
    assert summary["MEDIUM"] == 0
    assert summary["LOW"] == 1
    assert summary["total"] == 4
