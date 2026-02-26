import time
import requests
from logger import get_logger

log = get_logger(__name__)

# Cached docs fetches to avoid re-hitting AWS docs on every call
_docs_cache: dict = {}

# Local compliance mapping — zero latency, zero cost
COMPLIANCE_MAP = {
    "s3": {
        "CIS": ["2.1.1", "2.1.2", "2.1.5"],
        "PCI DSS": ["1.3.6", "7.2.1"],
        "SOC 2": ["CC6.1", "CC6.6"],
        "NIST SP 800-53": ["AC-3", "AC-21", "SC-7"],
        "ISO 27001": ["A.13.1.3", "A.18.1.3"],
    },
    "iam": {
        "CIS": ["1.3", "1.4", "1.10", "1.12"],
        "PCI DSS": ["8.2.1", "8.3", "8.3.1"],
        "SOC 2": ["CC6.1", "CC6.2"],
        "NIST SP 800-53": ["AC-2", "AC-3", "IA-2", "IA-5"],
        "ISO 27001": ["A.9.2.1", "A.9.2.3", "A.9.4.2"],
    },
    "ec2": {
        "CIS": ["4.1", "4.2"],
        "PCI DSS": ["1.2.1", "1.3.1"],
        "SOC 2": ["CC6.6", "CC6.7"],
        "NIST SP 800-53": ["AC-17", "SC-7", "CM-7"],
        "ISO 27001": ["A.13.1.1", "A.13.1.3"],
    },
    "cloudtrail": {
        "CIS": ["2.1", "2.2", "2.3"],
        "PCI DSS": ["10.1", "10.2", "10.3"],
        "SOC 2": ["CC7.2", "CC7.3"],
        "NIST SP 800-53": ["AU-2", "AU-3", "AU-12"],
        "ISO 27001": ["A.12.4.1", "A.12.4.3"],
    },
    "default": {
        "CIS": ["1.1"],
        "PCI DSS": ["6.3"],
        "SOC 2": ["CC7.1"],
        "NIST SP 800-53": ["SI-2"],
        "ISO 27001": ["A.12.6.1"],
    },
}

# Map Security Hub control IDs to AWS docs URLs
CONTROL_DOCS = {
    "S3":           "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html",
    "IAM":          "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html",
    "EC2":          "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html",
    "CloudTrail":   "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html",
    "Config":       "https://docs.aws.amazon.com/securityhub/latest/userguide/config-controls.html",
    "GuardDuty":    "https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html",
}


def lookup_cves(misconfiguration_type: str, service: str) -> dict:
    """
    Tool 1: Search NVD for CVEs related to an AWS misconfiguration.
    Free, no API key required. Rate limit: 5 requests / 30 seconds.
    """
    query = f"AWS {service} {misconfiguration_type}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 3}

    try:
        time.sleep(1)  # respect NVD rate limit
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = cve.get("descriptions", [{}])[0].get("value", "No description")
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0]["cvssData"].get("baseScore")
                    break
            cves.append({
                "id": cve.get("id"),
                "description": desc[:300],
                "cvss_score": score,
                "published": cve.get("published", "")[:10],
            })

        log.info(f"CVE lookup: {len(cves)} results for '{query}'")
        return {"query": query, "cves": cves}

    except Exception as e:
        log.warning(f"CVE lookup failed for '{query}': {e}")
        return {"query": query, "cves": [], "error": str(e)}


def fetch_aws_remediation(control_id: str) -> dict:
    """
    Tool 2: Fetch official AWS remediation guidance for a Security Hub control.
    Results are cached to avoid redundant fetches.
    """
    service = control_id.split(".")[0] if "." in control_id else control_id
    url = CONTROL_DOCS.get(service, CONTROL_DOCS.get("IAM"))

    if url in _docs_cache:
        log.info(f"Docs cache hit for {control_id}")
        return {"control_id": control_id, "url": url, "source": "cache"}

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        _docs_cache[url] = True
        log.info(f"Fetched AWS docs for control {control_id}")
        return {
            "control_id": control_id,
            "url": url,
            "remediation_hint": f"See official AWS Security Hub documentation for {control_id} remediation steps.",
            "source": "live",
        }
    except Exception as e:
        log.warning(f"Failed to fetch docs for {control_id}: {e}")
        return {"control_id": control_id, "url": url, "error": str(e)}


def check_compliance(finding_type: str, service: str) -> dict:
    """
    Tool 3: Return compliance control IDs for a finding type.
    Pure local lookup — zero latency, zero cost.
    """
    key = service.lower()
    mapping = COMPLIANCE_MAP.get(key, COMPLIANCE_MAP["default"])
    controls = []
    for framework, ids in mapping.items():
        for cid in ids:
            controls.append({"framework": framework, "control_id": cid})

    log.info(f"Compliance check: {len(controls)} controls for service={service}")
    return {"service": service, "finding_type": finding_type, "controls": controls}


# Tool schemas for Claude tool use API
TOOL_SCHEMAS = [
    {
        "name": "lookup_cves",
        "description": "Search NVD for CVEs related to a specific AWS misconfiguration type and service.",
        "input_schema": {
            "type": "object",
            "properties": {
                "misconfiguration_type": {"type": "string", "description": "Type of misconfiguration, e.g. 'public access enabled'"},
                "service": {"type": "string", "description": "AWS service name, e.g. 'S3', 'IAM', 'EC2'"},
            },
            "required": ["misconfiguration_type", "service"],
        },
    },
    {
        "name": "fetch_aws_remediation",
        "description": "Fetch official AWS remediation documentation URL for a Security Hub control ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "control_id": {"type": "string", "description": "Security Hub control ID, e.g. 'S3.2' or 'IAM.4'"},
            },
            "required": ["control_id"],
        },
    },
    {
        "name": "check_compliance",
        "description": "Get compliance control IDs across CIS, PCI DSS, SOC 2, NIST, and ISO 27001 for a finding type.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_type": {"type": "string", "description": "Description of the misconfiguration"},
                "service": {"type": "string", "description": "AWS service, e.g. 's3', 'iam', 'ec2', 'cloudtrail'"},
            },
            "required": ["finding_type", "service"],
        },
    },
]


def execute_tool(name: str, inputs: dict) -> str:
    """Dispatch a tool call from the agent loop and return result as a JSON string."""
    import json
    if name == "lookup_cves":
        result = lookup_cves(inputs["misconfiguration_type"], inputs["service"])
    elif name == "fetch_aws_remediation":
        result = fetch_aws_remediation(inputs["control_id"])
    elif name == "check_compliance":
        result = check_compliance(inputs["finding_type"], inputs["service"])
    else:
        result = {"error": f"Unknown tool: {name}"}
    return json.dumps(result)
