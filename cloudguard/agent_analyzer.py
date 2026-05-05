"""
Agentic Security Analyzer.

This module implements an enriched analysis pipeline for HIGH and CRITICAL
AWS Security Hub findings. It pre-fetches CVE data, AWS documentation, and
compliance mappings using the local tool functions, then injects the results
as context into a single NVIDIA NIM (Gemma 4) call — achieving the same
enrichment as a tool-calling agent without requiring function-calling support
from the model.
"""
from cloudguard.config import get_secret
import json
from cloudguard.tools import lookup_cves, fetch_aws_remediation, check_compliance
from cloudguard.analyzer import SYSTEM_PROMPT, analyze_finding, _extract_json
from cloudguard.logger import get_logger
from cloudguard.nvidia_client import nvidia_chat

log = get_logger(__name__)

# Agent enriches HIGH and CRITICAL findings with external tool calls
AGENT_SEVERITIES = {"CRITICAL", "HIGH"}

AGENT_SYSTEM_PROMPT = SYSTEM_PROMPT + """

You have been provided with pre-fetched enrichment data below. Use it to:
- Populate the "citations" array with NVD CVE URLs and AWS documentation URLs
- Fill "compliance_frameworks" with the exact control IDs listed
- Incorporate CVE descriptions into your "why_it_matters" and "plain_english" fields

Do NOT repeat the raw enrichment data verbatim — synthesize it into the structured JSON fields.
Return ONLY the JSON object. No other text whatsoever."""


def _build_enrichment_context(finding: dict) -> str:
    """
    Pre-fetch CVE, AWS docs, and compliance data for a finding and format as context.

    Args:
        finding (dict): The raw AWS Security Hub finding.

    Returns:
        str: A formatted string of enrichment data to inject into the prompt.
    """
    # Derive service and misconfiguration type from the finding
    types = finding.get("Types", ["Software and Configuration Checks"])
    finding_type = types[0] if types else "misconfiguration"
    title = finding.get("Title", "")
    resources = finding.get("Resources", [{}])
    resource_type = resources[0].get("Type", "AWS::IAM") if resources else "AWS::IAM"
    service = resource_type.split("::")[-1] if "::" in resource_type else "IAM"

    sections = []

    try:
        cve_data = lookup_cves(finding_type, service)
        cves = cve_data.get("cves", [])
        if cves:
            lines = [f"CVE Search Results for '{service} {finding_type}':"]
            for c in cves:
                lines.append(
                    f"  - {c['id']} (CVSS {c.get('cvss_score', 'N/A')}): "
                    f"{c['description'][:200]}  [URL: {c['nvd_url']}]"
                )
            sections.append("\n".join(lines))
        else:
            sections.append(f"CVE Search: No specific CVEs found for {service} {finding_type}.")
    except Exception as e:
        log.warning(f"CVE lookup failed: {e}")
        sections.append("CVE Search: Unavailable.")

    try:
        # Guess control ID from finding title (e.g. "S3.2", "IAM.4")
        control_id = f"{service}.1"
        for word in title.split():
            if "." in word and word.split(".")[0].isalpha():
                control_id = word
                break
        docs = fetch_aws_remediation(control_id)
        sections.append(
            f"AWS Remediation Docs for {control_id}: {docs.get('url', 'N/A')}"
        )
    except Exception as e:
        log.warning(f"AWS docs lookup failed: {e}")
        sections.append("AWS Docs: Unavailable.")

    try:
        compliance = check_compliance(finding_type, service)
        controls = compliance.get("controls", [])
        lines = ["Compliance Controls:"]
        for c in controls:
            lines.append(f"  - {c['framework']} {c['control_id']}")
        sections.append("\n".join(lines))
    except Exception as e:
        log.warning(f"Compliance lookup failed: {e}")
        sections.append("Compliance: Unavailable.")

    return "\n\n".join(sections)


def analyze_with_agent(finding: dict, api_key: str = None, max_tool_rounds: int = 5) -> dict:
    """
    Run an enriched analysis of a Security Hub finding using NVIDIA NIM.

    For HIGH and CRITICAL findings, tool results (CVEs, AWS docs, compliance
    mappings) are pre-fetched locally and injected as prompt context before
    calling the model. For LOW/MEDIUM findings, falls back to the standard
    `analyze_finding` path.

    Args:
        finding (dict): The raw AWS Security Hub finding dictionary.
        api_key (str, optional): NVIDIA API key.
        max_tool_rounds (int, optional): Unused — kept for API compatibility.

    Returns:
        dict: The structured analysis parsed from the model's JSON response,
              or an error payload.
    """
    sev = finding.get("Severity", {}).get("Label", "LOW")
    finding_id = finding.get("Id", "unknown")

    # Only run full enriched analysis for HIGH/CRITICAL
    if sev not in AGENT_SEVERITIES:
        log.info(f"Severity {sev} — using simple analysis | id={finding_id}")
        return analyze_finding(finding, api_key=api_key)

    key = api_key or get_secret("GROQ_API_KEY")
    if not key:
        raise ValueError("GROQ_API_KEY not set.")

    log.info(f"Agent analysis started | id={finding_id} severity={sev}")

    # Pre-fetch enrichment data locally
    enrichment = _build_enrichment_context(finding)
    log.info(f"Enrichment context built | id={finding_id}")

    finding_json = json.dumps(finding, indent=2)

    enriched_prompt = (
        f"ENRICHMENT DATA (use to populate citations and compliance fields):\n"
        f"{enrichment}\n\n"
        f"---\n\n"
        f"Analyze this AWS Security Hub finding:\n\n{finding_json}"
    )

    try:
        raw = nvidia_chat(
            messages=[{"role": "user", "content": enriched_prompt}],
            api_key=key,
            system_prompt=AGENT_SYSTEM_PROMPT,
            max_tokens=4096,
        )

        raw = _extract_json(raw)
        result = json.loads(raw)
        log.info(f"Agent analysis complete | id={finding_id} priority={result.get('priority')}")
        return result

    except json.JSONDecodeError as e:
        log.error(f"Agent returned invalid JSON | id={finding_id} error={e}")
        return {"error": f"Agent returned invalid JSON: {e}", "raw_response": raw}
    except RuntimeError as e:
        err = str(e)
        if "401" in err or "403" in err:
            return {"error": "Invalid NVIDIA API key. Check your GROQ_API_KEY."}
        if "429" in err:
            return {"error": "Rate limit hit. Wait 60 seconds and try again."}
        log.error(f"API error | id={finding_id} error={e}")
        return {"error": f"API error: {err}"}
    except Exception as e:
        log.error(f"Unexpected error | id={finding_id} error={e}")
        return {"error": f"Unexpected error: {str(e)}"}
