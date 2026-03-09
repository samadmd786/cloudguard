"""
Standard Security Finding Analyzer.

This module provides the core `analyze_finding` function, which takes a raw
AWS Security Hub finding (JSON) and sends it to the Anthropic Claude API using
a zero-shot prompt. It forces Claude to return a structured JSON response
detailing the risk, business impact, and specific remediation steps.
"""
import json
import anthropic
from cloudguard.logger import get_logger

log = get_logger(__name__)

# System prompt instructs Claude to act as a senior AWS security engineer
# and return ONLY valid JSON — no prose, no markdown fences
SYSTEM_PROMPT = """You are a senior AWS security engineer with 15 years of experience.
A user will give you an AWS Security Hub finding in JSON format.
You must analyze it and return ONLY a valid JSON object — no markdown, no code fences, no explanation.

Your JSON response must contain exactly these fields:

{
  "plain_english": "2-3 sentences explaining what is wrong. Reference the actual resource name from the finding.",
  "why_it_matters": "The real-world risk if this misconfiguration is exploited by an attacker.",
  "business_impact": {
    "data_risk": "Specific data exposure or loss risk.",
    "financial_risk": "Potential financial consequences.",
    "compliance_risk": "Which regulations or frameworks this violates and what the penalty could be."
  },
  "fix_steps": [
    {
      "step": "Human-readable description of what to do.",
      "cli_command": "The exact AWS CLI command to fix it, or empty string if not applicable."
    }
  ],
  "citations": [
    {
      "title": "Short descriptive label, e.g. 'AWS S3 Block Public Access'",
      "url": "The official URL for this reference, e.g. https://docs.aws.amazon.com/...",
      "source": "One of: AWS Documentation, NVD, CIS Benchmark, NIST, PCI DSS, AWS Security Blog, AWS Well-Architected"
    }
  ],
  "compliance_frameworks": ["List of specific control IDs, e.g. CIS 2.3, PCI DSS 1.3.6, NIST AC-3"],
  "priority": "One of: Immediate, Soon, Planned",
  "tldr": "One sentence written for a non-technical executive explaining the risk and urgency."
}

Rules:
- Always reference the actual resource name (bucket name, user name, security group ID) from the finding.
- fix_steps must have at least 2 steps, ideally 3-4.
- cli_command should be a real, runnable AWS CLI command where possible.
- citations must have at least 2 entries linking to official AWS documentation, NVD CVE pages, CIS benchmark references, or other authoritative security sources that support your remediation advice.
- Return ONLY the JSON object. No other text whatsoever."""


def analyze_finding(finding: dict, api_key: str = None) -> dict:
    """
    Send a Security Hub finding to Claude and return a structured analysis.

    This function uses a strict system prompt to force the LLM to return
    a valid JSON object matching the `SYSTEM_PROMPT` schema.

    Args:
        finding (dict): The raw AWS Security Hub finding dictionary.
        api_key (str, optional): Anthropic API key. If not provided, it falls
            back to the `ANTHROPIC_API_KEY` environment variable.

    Returns:
        dict: The structured analysis parsed from Claude's JSON response, or
              a dictionary containing an 'error' key if the API call fails.
    """
    from cloudguard.config import get_secret
    key = api_key or get_secret("ANTHROPIC_API_KEY")
    if not key:
        log.error("ANTHROPIC_API_KEY not set")
        raise ValueError(
            "ANTHROPIC_API_KEY not set. Export it in your shell or pass it directly."
        )

    client = anthropic.Anthropic(api_key=key)
    finding_id = finding.get("Id", "unknown")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    log.info(f"Analysis started | id={finding_id} severity={severity}")

    finding_json = json.dumps(finding, indent=2)

    # Call the Anthropic API with the finding injected into the user prompt.
    # We use a relatively high max_tokens (4000) to ensure the complete JSON
    # object (especially the fix_steps array) is returned without truncation.
    try:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze this AWS Security Hub finding:\n\n{finding_json}",
                }
            ],
        )

        raw = response.content[0].text.strip()

        # Strip accidental markdown fences if Claude adds them anyway
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        result = json.loads(raw)
        log.info(f"Analysis complete | id={finding_id} priority={result.get('priority')}")
        return result

    except json.JSONDecodeError as e:
        log.error(f"JSON parse error | id={finding_id} error={e}")
        return {"error": f"Claude returned invalid JSON: {e}", "raw_response": raw}
    except anthropic.AuthenticationError:
        log.error("Authentication failed — check ANTHROPIC_API_KEY")
        return {"error": "Invalid Anthropic API key. Check your ANTHROPIC_API_KEY."}
    except anthropic.RateLimitError:
        log.warning(f"Rate limit hit | id={finding_id}")
        return {"error": "Rate limit hit. Wait 60 seconds and try again."}
    except Exception as e:
        log.error(f"Unexpected error | id={finding_id} error={e}")
        return {"error": f"Unexpected error: {str(e)}"}


if __name__ == "__main__":
    # Quick smoke test — run: python analyzer.py
    import sys

    sample_file = "sample_findings/s3_public.json"
    if len(sys.argv) > 1:
        sample_file = sys.argv[1]

    print(f"Testing analyzer with: {sample_file}")

    with open(sample_file) as f:
        finding = json.load(f)

    result = analyze_finding(finding)

    if "error" in result:
        print(f"ERROR: {result['error']}")
    else:
        print(f"TL;DR:    {result.get('tldr')}")
        print(f"Priority: {result.get('priority')}")
        print(f"\nPlain English:\n  {result.get('plain_english')}")
        print(f"\nWhy It Matters:\n  {result.get('why_it_matters')}")
        print(f"\nFix Steps:")
        for i, step in enumerate(result.get("fix_steps", []), 1):
            print(f"  {i}. {step['step']}")
            if step.get("cli_command"):
                print(f"     $ {step['cli_command']}")
        print(f"\nCompliance: {', '.join(result.get('compliance_frameworks', []))}")
        print(f"\nFull JSON saved to result.json")
        with open("result.json", "w") as f:
            json.dump(result, f, indent=2)
