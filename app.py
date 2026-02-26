import os
import json
import streamlit as st
from analyzer import analyze_finding

st.set_page_config(
    page_title="CloudGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

* { font-family: 'Inter', sans-serif; }

/* Base */
.stApp { background: #080c14; color: #e2e8f0; }
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0d1220 0%, #0a0f1a 100%);
  border-right: 1px solid rgba(99,179,255,0.1);
}

/* Hide default Streamlit top bar padding */
[data-testid="stAppViewContainer"] { padding-top: 0; }
[data-testid="stHeader"] { background: transparent; }

/* Gradient page header */
.cg-header {
  background: linear-gradient(135deg, #0d1b40 0%, #0a1628 50%, #0d0d2b 100%);
  border: 1px solid rgba(99,179,255,0.15);
  border-radius: 16px;
  padding: 32px 36px;
  margin-bottom: 28px;
  position: relative;
  overflow: hidden;
}
.cg-header::before {
  content: '';
  position: absolute;
  top: -60px; right: -60px;
  width: 220px; height: 220px;
  background: radial-gradient(circle, rgba(99,179,255,0.12) 0%, transparent 70%);
  border-radius: 50%;
}
.cg-header h1 {
  font-size: 2rem; font-weight: 800; margin: 0;
  background: linear-gradient(90deg, #63b3ff, #a78bfa);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.cg-header p { margin: 6px 0 0; color: #64748b; font-size: 0.95rem; }

/* Severity badge */
.badge {
  display: inline-block;
  padding: 5px 16px;
  border-radius: 20px;
  font-weight: 700;
  font-size: 0.8rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 10px;
}
.badge-CRITICAL {
  background: rgba(248,81,73,0.12);
  color: #f85149;
  border: 1px solid rgba(248,81,73,0.5);
  box-shadow: 0 0 12px rgba(248,81,73,0.2);
}
.badge-HIGH {
  background: rgba(240,136,62,0.12);
  color: #f0883e;
  border: 1px solid rgba(240,136,62,0.5);
  box-shadow: 0 0 12px rgba(240,136,62,0.2);
}
.badge-MEDIUM {
  background: rgba(227,179,65,0.12);
  color: #e3b341;
  border: 1px solid rgba(227,179,65,0.5);
  box-shadow: 0 0 12px rgba(227,179,65,0.15);
}
.badge-LOW {
  background: rgba(63,185,80,0.12);
  color: #3fb950;
  border: 1px solid rgba(63,185,80,0.5);
  box-shadow: 0 0 12px rgba(63,185,80,0.15);
}

/* Priority */
.priority-Immediate { color: #f85149; font-weight: 700; font-size: 0.9rem; }
.priority-Soon      { color: #f0883e; font-weight: 700; font-size: 0.9rem; }
.priority-Planned   { color: #3fb950; font-weight: 700; font-size: 0.9rem; }

/* TL;DR */
.tldr-box {
  background: linear-gradient(135deg, rgba(99,179,255,0.07), rgba(167,139,250,0.07));
  border: 1px solid rgba(99,179,255,0.2);
  border-left: 4px solid #63b3ff;
  border-radius: 10px;
  padding: 16px 20px;
  margin: 14px 0 22px;
  font-size: 1rem;
  color: #cbd5e1;
  line-height: 1.6;
}

/* Section header */
.section-header {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #4a6fa5;
  margin: 24px 0 10px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-header::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, rgba(99,179,255,0.15), transparent);
}

/* Impact card */
.impact-card {
  background: linear-gradient(135deg, #0f1a2e, #0d1525);
  border: 1px solid rgba(99,179,255,0.1);
  border-radius: 10px;
  padding: 16px;
  height: 100%;
  transition: border-color 0.2s;
}
.impact-card:hover { border-color: rgba(99,179,255,0.3); }
.impact-card h4 {
  margin: 0 0 8px;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #4a6fa5;
}
.impact-card p { margin: 0; font-size: 0.88rem; color: #94a3b8; line-height: 1.5; }

/* Compliance tags */
.tag {
  display: inline-block;
  background: rgba(99,179,255,0.08);
  color: #63b3ff;
  border: 1px solid rgba(99,179,255,0.25);
  border-radius: 12px;
  padding: 3px 12px;
  font-size: 0.78rem;
  margin: 3px 3px;
  font-weight: 500;
}

/* Raw JSON panel */
.json-panel {
  background: #0d1220;
  border: 1px solid rgba(99,179,255,0.1);
  border-radius: 10px;
  padding: 16px;
}

/* Sidebar logo text */
.sidebar-logo {
  font-size: 1.2rem;
  font-weight: 800;
  background: linear-gradient(90deg, #63b3ff, #a78bfa);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
</style>
""", unsafe_allow_html=True)



SAMPLE_DIR = "sample_findings"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def get_api_key() -> str:
    """Read API key from environment, then Streamlit secrets, then sidebar input."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        try:
            key = st.secrets.get("ANTHROPIC_API_KEY", "")
        except Exception:
            pass
    return key

def list_samples() -> list[str]:
    if not os.path.isdir(SAMPLE_DIR):
        return []
    files = [f for f in os.listdir(SAMPLE_DIR) if f.endswith(".json")]
    return sorted(files, key=lambda f: SEVERITY_ORDER.get(
        json.load(open(f"{SAMPLE_DIR}/{f}")).get("Severity", {}).get("Label", "LOW"), 99
    ))

def severity_badge(label: str) -> str:
    return f'<span class="badge badge-{label}">{label}</span>'

def priority_span(p: str) -> str:
    return f'<span class="priority-{p}">⚡ {p}</span>'

def render_analysis(finding: dict, result: dict):
    """Render the structured analysis result."""
    sev = finding.get("Severity", {}).get("Label", "UNKNOWN")
    title = finding.get("Title", "Unknown Finding")

    st.markdown(severity_badge(sev), unsafe_allow_html=True)
    st.markdown(f"### {title}")
    st.markdown(priority_span(result.get("priority", "—")), unsafe_allow_html=True)

    # TL;DR
    st.markdown(f'<div class="tldr-box">💬 <strong>TL;DR</strong><br>{result["tldr"]}</div>',
                unsafe_allow_html=True)

    # Plain English
    st.markdown('<div class="section-header">What happened</div>', unsafe_allow_html=True)
    st.markdown(result.get("plain_english", ""))

    # Why it matters
    st.markdown('<div class="section-header">Why it matters</div>', unsafe_allow_html=True)
    st.markdown(result.get("why_it_matters", ""))

    # Business impact — three columns
    st.markdown('<div class="section-header">Business impact</div>', unsafe_allow_html=True)
    impact = result.get("business_impact", {})
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'''<div class="impact-card">
            <h4>🗄️ Data Risk</h4><p>{impact.get("data_risk","—")}</p></div>''',
            unsafe_allow_html=True)
    with c2:
        st.markdown(f'''<div class="impact-card">
            <h4>💰 Financial Risk</h4><p>{impact.get("financial_risk","—")}</p></div>''',
            unsafe_allow_html=True)
    with c3:
        st.markdown(f'''<div class="impact-card">
            <h4>📋 Compliance Risk</h4><p>{impact.get("compliance_risk","—")}</p></div>''',
            unsafe_allow_html=True)

    # Fix steps
    st.markdown('<div class="section-header">How to fix it</div>', unsafe_allow_html=True)
    for i, step in enumerate(result.get("fix_steps", []), 1):
        with st.expander(f"Step {i}: {step['step']}", expanded=True):
            if step.get("cli_command"):
                st.code(step["cli_command"], language="bash", wrap_lines=True)


    # Compliance tags
    frameworks = result.get("compliance_frameworks", [])
    if frameworks:
        st.markdown('<div class="section-header">Compliance frameworks</div>', unsafe_allow_html=True)
        tags_html = " ".join(f'<span class="tag">{f}</span>' for f in frameworks)
        st.markdown(tags_html, unsafe_allow_html=True)



with st.sidebar:
    st.markdown('<div class="sidebar-logo">🛡️ CloudGuard AI</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    env_key = get_api_key()
    if env_key:
        st.success("API key loaded ✓")
        sidebar_key = env_key
    else:
        sidebar_key = st.text_input(
            "Anthropic API Key",
            type="password",
            placeholder="sk-ant-...",
            help="Set ANTHROPIC_API_KEY in your environment to skip this."
        )

    st.markdown("<br>", unsafe_allow_html=True)
    input_method = st.radio(
        "Input method",
        ["📂 Sample finding", "📋 Paste JSON", "📁 Upload .json file"],
        index=0,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    preview_mode = st.toggle(
        "⚡ UI Preview Mode",
        value=True,
        help="Loads a mock result instantly — no API call. Great for UI iteration."
    )
    if preview_mode:
        st.caption("Preview active — no API calls will be made.")

st.markdown("""
<div class="cg-header">
  <h1>🛡️ CloudGuard AI</h1>
  <p>AWS Security Hub Misconfiguration Analyzer</p>
</div>
""", unsafe_allow_html=True)

finding = None
finding_source = None

# Sample selector
if input_method == "📂 Sample finding":
    samples = list_samples()
    if not samples:
        st.warning("No sample findings found in sample_findings/ directory.")
    else:
        labels = {
            "s3_public.json":    "🔴 CRITICAL — S3 bucket publicly readable",
            "root_keys.json":    "🔴 CRITICAL — Root account has active access keys",
            "ssh_open.json":     "🟠 HIGH — SSH open to the internet (0.0.0.0/0)",
            "mfa_disabled.json": "🟠 HIGH — MFA not enabled for IAM user",
            "cloudtrail.json":   "🟡 MEDIUM — CloudTrail logging disabled",
        }
        choice = st.selectbox(
            "Select a sample finding",
            samples,
            format_func=lambda f: labels.get(f, f),
        )
        if choice:
            with open(f"{SAMPLE_DIR}/{choice}") as fp:
                finding = json.load(fp)
            finding_source = choice

# Paste JSON
elif input_method == "📋 Paste JSON":
    pasted = st.text_area(
        "Paste your Security Hub finding JSON here",
        height=280,
        placeholder='{ "SchemaVersion": "2018-10-08", ... }',
    )
    if pasted.strip():
        try:
            finding = json.loads(pasted)
            finding_source = "pasted JSON"
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")

# File upload
elif input_method == "📁 Upload .json file":
    uploaded = st.file_uploader("Upload a Security Hub finding .json file", type="json")
    if uploaded:
        try:
            finding = json.load(uploaded)
            finding_source = uploaded.name
        except Exception as e:
            st.error(f"Could not read file: {e}")

if finding:
    left, right = st.columns([1, 1.6], gap="large")

    with left:
        st.markdown('<div class="section-header">Raw Finding</div>', unsafe_allow_html=True)
        st.json(finding, expanded=False)

    with right:
        st.markdown('<div class="section-header">Analysis</div>', unsafe_allow_html=True)

        mode_prefix = "preview" if preview_mode else "live"
        cache_key = f"{mode_prefix}_{finding_source}_{finding.get('Id','')}"

        if cache_key in st.session_state:
            render_analysis(finding, st.session_state[cache_key])
            st.caption("⚡ Cached — no API call")
        else:
            analyze_clicked = st.button("🔍 Analyze Finding", type="primary", use_container_width=True)

            if analyze_clicked:
                if preview_mode:
                    with open("tests/mock_response.json") as f:
                        result = json.load(f)
                    st.session_state[cache_key] = result
                    st.rerun()
                elif not sidebar_key:
                    st.error("No API key found. Set ANTHROPIC_API_KEY or enter in the sidebar.")
                else:
                    with st.spinner("Analyzing finding..."):
                        result = analyze_finding(finding, api_key=sidebar_key)
                    if "error" in result:
                        st.error(f"Analysis failed: {result['error']}")
                    else:
                        st.session_state[cache_key] = result
                        st.rerun()

else:
    st.markdown("""
    <div style="text-align:center; padding: 60px 20px; color: #334155;">
      <div style="font-size: 3rem; margin-bottom: 16px;">🛡️</div>
      <div style="font-size: 1.1rem; font-weight: 600; color: #475569;">Select a finding to get started</div>
      <div style="font-size: 0.88rem; margin-top: 8px;">Choose from the sidebar or paste your own JSON</div>
    </div>
    """, unsafe_allow_html=True)
