import pytest
import json
from pytest_mock import MockerFixture
from cloudguard.agent_analyzer import analyze_with_agent

@pytest.fixture
def mock_finding():
    return {
        "Id": "test-finding-1",
        "Title": "S3 bucket is publicly readable",
        "Severity": {"Label": "CRITICAL"},
        "Resources": [{"Id": "arn:aws:s3:::my-public-bucket"}]
    }

def test_analyze_with_agent_low_severity_fallback(mocker: MockerFixture):
    # LOW severity should fallback to analyze_finding without starting the agent loop
    mock_analyze = mocker.patch("cloudguard.agent_analyzer.analyze_finding", return_value={"status": "fallback"})
    
    finding = {"Severity": {"Label": "LOW"}, "Id": "low-finding"}
    result = analyze_with_agent(finding, api_key="test_key")
    
    assert result == {"status": "fallback"}
    mock_analyze.assert_called_once()

def test_analyze_with_agent_success(mocker: MockerFixture, mock_finding):
    mock_client = mocker.MagicMock()
    mocker.patch("cloudguard.agent_analyzer.anthropic.Anthropic", return_value=mock_client)
    
    # Simulate Claude responding with `end_turn` and text block
    mock_response = mocker.MagicMock()
    mock_response.stop_reason = "end_turn"
    
    mock_block = mocker.MagicMock()
    mock_block.text = '{"priority": "Immediate", "tldr": "Fix it"}'
    mock_response.content = [mock_block]
    
    mock_client.messages.create.return_value = mock_response
    
    result = analyze_with_agent(mock_finding, api_key="test_key")
    
    assert result["priority"] == "Immediate"
    assert result["tldr"] == "Fix it"
    mock_client.messages.create.assert_called_once()

def test_analyze_with_agent_executes_tool(mocker: MockerFixture, mock_finding):
    mock_client = mocker.MagicMock()
    mocker.patch("cloudguard.agent_analyzer.anthropic.Anthropic", return_value=mock_client)
    
    # Round 1: Claude asks for a tool call
    mock_resp1 = mocker.MagicMock()
    mock_resp1.stop_reason = "tool_use"
    mock_tool_block = mocker.MagicMock()
    mock_tool_block.type = "tool_use"
    mock_tool_block.id = "tool1"
    mock_tool_block.name = "fetch_aws_remediation"
    mock_tool_block.input = {"control_id": "S3.2"}
    mock_resp1.content = [mock_tool_block]
    
    # Round 2: Claude returns final result
    mock_resp2 = mocker.MagicMock()
    mock_resp2.stop_reason = "end_turn"
    mock_text_block = mocker.MagicMock()
    mock_text_block.text = '{"priority": "High", "tldr": "Tool used"}'
    mock_resp2.content = [mock_text_block]
    
    mock_client.messages.create.side_effect = [mock_resp1, mock_resp2]
    
    # Mock the tool output
    mock_execute_tool = mocker.patch("cloudguard.agent_analyzer.execute_tool", return_value='{"url": "https://docs.aws.amazon.com/..."}')
    
    result = analyze_with_agent(mock_finding, api_key="test_key")
    
    assert result["priority"] == "High"
    mock_execute_tool.assert_called_once_with("fetch_aws_remediation", {"control_id": "S3.2"})
    assert mock_client.messages.create.call_count == 2

def test_analyze_with_agent_invalid_json(mocker: MockerFixture, mock_finding):
    mock_client = mocker.MagicMock()
    mocker.patch("cloudguard.agent_analyzer.anthropic.Anthropic", return_value=mock_client)
    
    mock_response = mocker.MagicMock()
    mock_response.stop_reason = "end_turn"
    mock_block = mocker.MagicMock()
    mock_block.text = '{"missing_bracket": "yes"' # Broken JSON
    mock_response.content = [mock_block]
    
    mock_client.messages.create.return_value = mock_response
    
    result = analyze_with_agent(mock_finding, api_key="test_key")
    
    assert "error" in result
    assert "Agent returned invalid JSON" in result["error"]
