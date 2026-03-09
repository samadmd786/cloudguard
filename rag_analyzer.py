"""
RAG-Enhanced Security Analyzer.

This module retrieves similar past findings from the local `memory_store`
(ChromaDB vector store) and injects them into the Claude system prompt before
running the analysis. This allows the model to identify recurring patterns
and tailor remediation steps based on the organization's history.
"""
import json
from analyzer import analyze_finding, SYSTEM_PROMPT
from memory_store import retrieve_similar, store
from logger import get_logger

log = get_logger(__name__)

RAG_PREAMBLE = """
You have access to past analyses of similar findings from this organisation.
Use them to:
- Identify recurring patterns (mention if this finding is seen repeatedly)
- Tailor remediation steps to the organisation's environment
- Reference past priorities if consistent

Past similar findings:
{context}

Now analyse the new finding below. Return the same structured JSON format.
"""


def _build_context(similar: list[dict]) -> str:
    """
    Format retrieved similar findings into a readable context block.

    Args:
        similar (list[dict]): A list of past findings retrieved from memory.

    Returns:
        str: A formatted string listing past findings, or a fallback message if empty.
    """
    if not similar:
        return "No similar past findings."
    lines = []
    for i, item in enumerate(similar, 1):
        lines.append(
            f"{i}. [{item['severity']}] {item['title']} "
            f"(priority: {item['priority']}, similarity: {item['similarity']})"
        )
    return "\n".join(lines)


def analyze_with_rag(finding: dict, api_key: str = None) -> dict:
    """
    Perform a RAG-enhanced analysis of a Security Hub finding.

    Workflow:
    1. Retrieve up to 3 similar past findings from the vector database.
    2. Inject them as context into the `RAG_PREAMBLE` system prompt.
    3. Run standard Claude analysis using the enriched prompt.
    4. Store the new successful result back into memory for future use.

    Args:
        finding (dict): The raw AWS Security Hub finding dictionary.
        api_key (str, optional): Anthropic API key.

    Returns:
        dict: The structured analysis parsed from Claude's JSON response,
              including a 'rag_context_count' metric.
    """
    finding_id = finding.get("Id", "unknown")
    log.info(f"RAG analysis started | id={finding_id}")

    similar = retrieve_similar(finding, n_results=3)
    context = _build_context(similar)
    log.info(f"Injecting {len(similar)} similar findings as context")

    # Build enriched system prompt
    rag_system_prompt = SYSTEM_PROMPT + RAG_PREAMBLE.format(context=context)

    # Run analysis with enriched prompt
    import json as _json
    import anthropic
    from config import get_secret

    key = api_key or get_secret("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY not set.")

    client = anthropic.Anthropic(api_key=key)
    finding_json = _json.dumps(finding, indent=2)

    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4000,
            system=rag_system_prompt,
            messages=[{"role": "user", "content": f"Analyse this finding:\n\n{finding_json}"}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = _json.loads(raw)
        result["rag_context_count"] = len(similar)  # expose to UI
        log.info(f"RAG analysis complete | id={finding_id} similar_used={len(similar)}")

        # Store the new result so future analyses benefit from it
        store(finding, result)
        return result

    except _json.JSONDecodeError as e:
        log.error(f"RAG JSON parse error | id={finding_id}: {e}")
        return {"error": f"JSON parse error: {e}"}
    except Exception as e:
        log.error(f"RAG analysis error | id={finding_id}: {e}")
        return {"error": str(e)}
