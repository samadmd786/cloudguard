import pytest
from unittest.mock import patch
import json
import os
import memory_store

@pytest.fixture
def mock_store(tmp_path):
    """Fixture to mock the storage file to a temp directory."""
    temp_file = tmp_path / "findings.json"
    with patch("memory_store.STORE_FILE", str(temp_file)):
        with patch("memory_store.STORE_DIR", str(tmp_path)):
            yield str(temp_file)

@pytest.fixture
def mock_embedding():
    """Fixture to mock the sentence-transformer embedding model."""
    with patch("memory_store._get_model") as mock_model_func:
        mock_model = mock_model_func.return_value
        # Return a deterministic [0.1, 0.2] list as the fake embedding
        mock_model.encode.return_value.tolist.return_value = [0.1, 0.2]
        yield mock_model

def test_store_and_count(mock_store, mock_embedding):
    """Test storing a finding and incrementing the count."""
    finding = {"Id": "finding-1", "Title": "Test Finding", "Resources": [{"Type": "AwsS3Bucket"}]}
    analysis = {"priority": "High", "plain_english": "Test desc"}
    
    assert memory_store.count() == 0
    doc_id = memory_store.store(finding, analysis)
    
    assert doc_id != ""
    assert memory_store.count() == 1
    
    # Store the exact same finding — it should upsert and keep count at 1
    doc_id2 = memory_store.store(finding, analysis)
    assert doc_id == doc_id2
    assert memory_store.count() == 1

def test_store_handles_error_analysis(mock_store):
    """Test storing skips analyses that contain 'error' keys."""
    finding = {"Id": "finding-err"}
    analysis = {"error": "Claude failed"}
    
    doc_id = memory_store.store(finding, analysis)
    assert doc_id == ""
    assert memory_store.count() == 0

def test_retrieve_similar(mock_store, mock_embedding):
    """Test retrieving similar findings using mock cosine similarity."""
    finding1 = {"Id": "f-1", "Title": "S3 Public"}
    analysis1 = {"priority": "High", "tldr": "Fix it."}
    
    finding2 = {"Id": "f-2", "Title": "IAM Root Key"}
    analysis2 = {"priority": "Immediate", "tldr": "Fix it fast."}
    
    memory_store.store(finding1, analysis1)
    memory_store.store(finding2, analysis2)
    
    # Now query similarity against finding 3
    finding3 = {"Id": "f-3", "Title": "Another S3 issue"}
    results = memory_store.retrieve_similar(finding3, n_results=1)
    
    assert len(results) == 1
    # Because our mock embedding returns the exact same vector [0.1, 0.2] every time,
    # the similarity score will be exactly 1.0. 
    assert results[0]["similarity"] == 1.0
    assert "analysis_json" in results[0]

def test_get_all(mock_store, mock_embedding):
    """Test get_all returns metadata stripped of large embeddings."""
    finding1 = {"Id": "f-1", "Title": "S3 Public"}
    analysis1 = {"priority": "High"}
    
    memory_store.store(finding1, analysis1)
    metrics = memory_store.get_all(limit=10)
    
    assert len(metrics) == 1
    assert metrics[0]["id"] != ""
    assert metrics[0]["title"] == "S3 Public"
    assert metrics[0]["priority"] == "High"
    assert "embedding" not in metrics[0]  # Should be stripped
