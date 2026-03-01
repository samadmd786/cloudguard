import pytest
from unittest.mock import patch
import json
import rag_analyzer

def test_build_context_empty():
    """Test building context when no similar findings are found."""
    context = rag_analyzer._build_context([])
    assert "No similar past findings" in context

def test_build_context_with_results():
    """Test building a formatted context block from memory results."""
    similar = [
        {"severity": "CRITICAL", "title": "S3 Public", "priority": "Immediate", "similarity": 0.95},
        {"severity": "HIGH", "title": "IAM Key", "priority": "Soon", "similarity": 0.82}
    ]
    context = rag_analyzer._build_context(similar)
    assert "1. [CRITICAL] S3 Public (priority: Immediate, similarity: 0.95)" in context
    assert "2. [HIGH] IAM Key (priority: Soon, similarity: 0.82)" in context

@patch("rag_analyzer.retrieve_similar")
@patch("rag_analyzer.store")
@patch("anthropic.Anthropic")
def test_analyze_with_rag_success(mock_anthropic, mock_store, mock_retrieve, monkeypatch):
    """Test the full RAG pipeline successfully calls Claude and stores the result."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    finding = {"Id": "new-finding-123", "Title": "Test Issue"}
    
    # Mock similar findings from memory
    mock_retrieve.return_value = [
        {"severity": "HIGH", "title": "Old Issue", "priority": "Soon", "similarity": 0.90}
    ]

    # Mock Claude's API JSON response
    mock_client = mock_anthropic.return_value
    mock_response = mock_client.messages.create.return_value
    
    class MockBlock:
        def __init__(self, text):
            self.text = text
            
    mock_response.content = [MockBlock('{"priority": "Immediate", "tldr": "Fix it."}')]

    # Run the function
    result = rag_analyzer.analyze_with_rag(finding)

    # Asserts exactly 1 similar finding was returned and appended to result metric
    assert result["rag_context_count"] == 1
    assert result["priority"] == "Immediate"

    # Asserts memory store was called to save the new analysis
    mock_store.assert_called_once_with(finding, result)

@patch("rag_analyzer.retrieve_similar")
@patch("anthropic.Anthropic")
def test_analyze_with_rag_invalid_json(mock_anthropic, mock_retrieve, monkeypatch):
    """Test the RAG pipeline handles invalid JSON from Claude gracefully without crashing."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    finding = {"Id": "bad-finding"}
    mock_retrieve.return_value = []

    # Mock Claude's API returning broken JSON
    mock_client = mock_anthropic.return_value
    mock_response = mock_client.messages.create.return_value
    
    class MockBlock:
        def __init__(self, text):
            self.text = text
            
    mock_response.content = [MockBlock('{broken_json')]

    # Run the function
    result = rag_analyzer.analyze_with_rag(finding)

    assert "error" in result
    assert "JSON parse error" in result["error"]
