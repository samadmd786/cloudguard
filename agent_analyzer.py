import os
import json
import anthropic
from tools import TOOL_SCHEMAS, execute_tool
from analyzer import SYSTEM_PROMPT, analyze_finding
from logger import get_logger

log = get_logger(__name__)

# Agent enriches HIGH and CRITICAL findings with external tool calls
AGENT_SEVERITIES = {"CRITICAL", "HIGH"}

AGENT_SYSTEM_PROMPT = SYSTEM_PROMPT + """

You also have access to three tools:
- lookup_cves: search for known CVEs related to this misconfiguration
- fetch_aws_remediation: get the official AWS remediation documentation URL
- check_compliance: get specific compliance control IDs (CIS, PCI DSS, SOC 2, NIST, ISO 27001)

For CRITICAL and HIGH severity findings, you MUST call all three tools before producing your final JSON response.
For MEDIUM and LOW severity findings, only call check_compliance.

After gathering tool results, produce the same structured JSON output as before.
Do NOT include tool results as raw JSON in your response — synthesize them into the structured fields."""


def analyze_with_agent(finding: dict, api_key: str = None, max_tool_rounds: int = 5) -> dict:
    """
    Agent loop: Claude calls tools autonomously to enrich the analysis,
    then returns the same structured dict as analyze_finding().
    For LOW/MEDIUM findings, falls back to simple analysis.
    """
    sev = finding.get("Severity", {}).get("Label", "LOW")
    finding_id = finding.get("Id", "unknown")

    # Only run full agent for HIGH/CRITICAL
    if sev not in AGENT_SEVERITIES:
        log.info(f"Severity {sev} — using simple analysis | id={finding_id}")
        return analyze_finding(finding, api_key=api_key)

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY not set.")

    client = anthropic.Anthropic(api_key=key)
    finding_json = json.dumps(finding, indent=2)
    log.info(f"Agent analysis started | id={finding_id} severity={sev}")

    messages = [
        {
            "role": "user",
            "content": f"Analyze this AWS Security Hub finding:\n\n{finding_json}",
        }
    ]

    for round_num in range(max_tool_rounds):
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2500,
            system=AGENT_SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        log.info(f"Agent round {round_num + 1} stop_reason={response.stop_reason} | id={finding_id}")

        if response.stop_reason == "end_turn":
            # Claude is done — extract the final JSON text response
            for block in response.content:
                if hasattr(block, "text"):
                    raw = block.text.strip()
                    if raw.startswith("```"):
                        raw = raw.split("```")[1]
                        if raw.startswith("json"):
                            raw = raw[4:]
                        raw = raw.strip()
                    try:
                        result = json.loads(raw)
                        log.info(f"Agent analysis complete | id={finding_id} priority={result.get('priority')}")
                        return result
                    except json.JSONDecodeError as e:
                        log.error(f"Agent returned invalid JSON | id={finding_id} error={e}")
                        return {"error": f"Agent returned invalid JSON: {e}", "raw_response": raw}
            return {"error": "Agent returned no text content"}

        if response.stop_reason == "tool_use":
            # Append Claude's response with tool calls to messages
            messages.append({"role": "assistant", "content": response.content})

            # Execute each requested tool and collect results
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    log.info(f"Agent calling tool={block.name} inputs={block.input} | id={finding_id}")
                    result_str = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })

            messages.append({"role": "user", "content": tool_results})

    log.error(f"Agent exceeded max_tool_rounds={max_tool_rounds} | id={finding_id}")
    return {"error": f"Agent did not finish within {max_tool_rounds} tool rounds."}
