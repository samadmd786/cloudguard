"""
Persistent Vector Memory Store.

Uses `sentence-transformers` to generate embeddings and a local JSON file
as the backing store. This natively supports RAG and Risk Profiling without
requiring a heavier database dependency like ChromaDB or pgvector.

Store location: `.chroma/findings.json` (gitignored)
"""
import json
import hashlib
import os
import math
from datetime import datetime, timezone

from logger import get_logger

log = get_logger(__name__)

STORE_DIR = ".chroma"
STORE_FILE = os.path.join(STORE_DIR, "findings.json")
EMBED_MODEL = "all-MiniLM-L6-v2"

_model = None  # lazy-loaded


def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBED_MODEL)
        log.info(f"Embedding model loaded: {EMBED_MODEL}")
    return _model


def _load_store() -> list[dict]:
    if not os.path.exists(STORE_FILE):
        return []
    try:
        with open(STORE_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_store(records: list[dict]):
    os.makedirs(STORE_DIR, exist_ok=True)
    with open(STORE_FILE, "w") as f:
        json.dump(records, f)


def _make_id(finding: dict) -> str:
    raw = finding.get("Id", json.dumps(finding, sort_keys=True))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _text_for_embedding(finding: dict, analysis: dict) -> str:
    parts = [
        finding.get("Title", ""),
        finding.get("Description", ""),
        analysis.get("plain_english", ""),
        analysis.get("why_it_matters", ""),
        analysis.get("tldr", ""),
        " ".join(analysis.get("compliance_frameworks", [])),
    ]
    return " | ".join(p for p in parts if p)


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def store(finding: dict, analysis: dict) -> str:
    """
    Embed and persist a finding and its completed analysis.

    Generates a text document combining the finding details and the Claude analysis,
    embeds it using `sentence-transformers`, and saves the record to the JSON store.
    If a record with the same finding ID exists, it is overwritten (upsert).

    Args:
        finding (dict): The raw AWS Security Hub finding.
        analysis (dict): The parsed JSON analysis from Claude.

    Returns:
        str: The generated unique document ID, or an empty string if storage failed.
    """
    if "error" in analysis:
        return ""
    try:
        model = _get_model()
        doc = _text_for_embedding(finding, analysis)
        embedding = model.encode(doc).tolist()
        doc_id = _make_id(finding)

        record = {
            "id": doc_id,
            "finding_id": finding.get("Id", "")[:512],
            "title": finding.get("Title", "")[:256],
            "severity": finding.get("Severity", {}).get("Label", "UNKNOWN"),
            "priority": analysis.get("priority", ""),
            "service": (finding.get("Resources") or [{}])[0].get("Type", "")[:128],
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "analysis_json": json.dumps(analysis)[:2048],
            "embedding": embedding,
        }

        records = _load_store()
        # Upsert — replace existing record with same ID
        records = [r for r in records if r.get("id") != doc_id]
        records.append(record)
        _save_store(records)
        log.info(f"Stored finding | id={doc_id} severity={record['severity']}")
        return doc_id

    except Exception as e:
        log.error(f"Failed to store finding: {e}")
        return ""


def retrieve_similar(finding: dict, n_results: int = 3) -> list[dict]:
    """
    Find the most semantically similar past findings to a new finding.

    Embeds the new finding's title and description, then calculates the cosine
    similarity against all stored embeddings to find historical matches.

    Args:
        finding (dict): The raw AWS Security Hub finding to compare against.
        n_results (int, optional): The maximum number of similar findings to return. Defaults to 3.

    Returns:
        list[dict]: A list of the most similar past findings and their similarity scores.
    """
    try:
        records = _load_store()
        if not records:
            return []

        model = _get_model()
        query_text = (
            f"{finding.get('Title', '')} "
            f"{finding.get('Description', '')} "
            f"{(finding.get('Resources') or [{}])[0].get('Type', '')}"
        )
        query_vec = model.encode(query_text).tolist()
        current_id = _make_id(finding)

        scored = []
        for r in records:
            if r.get("id") == current_id:
                continue
            emb = r.get("embedding", [])
            if emb:
                sim = _cosine(query_vec, emb)
                scored.append((sim, r))

        scored.sort(key=lambda x: x[0], reverse=True)

        similar = []
        for sim, r in scored[:n_results]:
            similar.append({
                "title": r.get("title", ""),
                "severity": r.get("severity", ""),
                "priority": r.get("priority", ""),
                "similarity": round(sim, 3),
                "analysis_json": r.get("analysis_json", "{}"),
            })

        log.info(f"Retrieved {len(similar)} similar findings")
        return similar

    except Exception as e:
        log.error(f"Failed to retrieve similar findings: {e}")
        return []


def get_all(limit: int = 500) -> list[dict]:
    """
    Return metadata for all stored findings, stripped of large embeddings.

    Used by the `risk_profiler` to aggregate org-wide statistics.

    Args:
        limit (int, optional): Maximum number of recent records to return. Defaults to 500.

    Returns:
        list[dict]: A list of stored finding metadata dictionaries.
    """
    try:
        records = _load_store()
        return [{k: v for k, v in r.items() if k != "embedding"} for r in records[-limit:]]
    except Exception as e:
        log.error(f"Failed to fetch all findings: {e}")
        return []


def count() -> int:
    """
    Return the total number of findings currently stored in memory.

    Returns:
        int: The integer count of stored findings.
    """
    return len(_load_store())
