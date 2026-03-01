import os
import json
from datetime import datetime
import streamlit as st
from dotenv import load_dotenv
from analyzer import analyze_finding
from agent_analyzer import analyze_with_agent
from aws_connector import verify_aws_connection, get_findings, get_summary
from rag_analyzer import analyze_with_rag
from risk_profiler import get_profile
from memory_store import count as memory_count
from logger import get_logger

load_dotenv(override=False)  # os.environ always wins over .env

# Strip .env placeholder values so they don't block real credentials
_PLACEHOLDER_MARKERS = ("your-", "your_", "<", "example", "changeme", "replace")
for _var in ("ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
    _val = os.environ.get(_var, "")
    if any(_val.lower().startswith(m) for m in _PLACEHOLDER_MARKERS):
        os.environ.pop(_var, None)

log = get_logger(__name__)

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

def add_activity(message: str, level: str = "info"):
    """Append a timestamped event to the session activity log."""
    if "activity" not in st.session_state:
        st.session_state["activity"] = []
    icon = "🟢" if level == "info" else "🔴"
    st.session_state["activity"].append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "icon": icon,
        "message": message,
    })
    st.session_state["activity"] = st.session_state["activity"][-10:]


RATE_LIMIT = 20          # max analyses per session per hour
RATE_WINDOW = 3600       # seconds

def check_rate_limit() -> bool:
    """
    Check if the current session has exceeded the rate limit.
    Returns True (and shows a warning) if the limit is reached.
    Caller should return / st.stop() when this returns True.
    """
    import time
    now = time.time()
    calls = st.session_state.get("rate_calls", [])
    calls = [t for t in calls if now - t < RATE_WINDOW]  # drop expired
    if len(calls) >= RATE_LIMIT:
        remaining = int(RATE_WINDOW - (now - calls[0]))
        mins = remaining // 60
        st.warning(
            f"⚠️ Rate limit reached — {RATE_LIMIT} analyses per hour per session. "
            f"Try again in {mins} min."
        )
        return True
    calls.append(now)
    st.session_state["rate_calls"] = calls
    return False

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

    # Export buttons
    st.markdown('<div class="section-header">Export report</div>', unsafe_allow_html=True)
    from exporter import to_markdown, to_pdf
    import hashlib
    _eid = hashlib.md5(finding.get("Id", finding.get("Title", "report")).encode()).hexdigest()[:8]
    _slug = finding.get("Title", "report")[:30].replace(" ", "_").lower()

    dcol1, dcol2 = st.columns(2)
    with dcol1:
        st.download_button(
            "📄 Download Markdown",
            data=to_markdown(finding, result),
            file_name=f"cloudguard_{_slug}.md",
            mime="text/markdown",
            use_container_width=True,
            key=f"dl_md_{_eid}",
        )
    with dcol2:
        try:
            pdf_bytes = to_pdf(finding, result)
            st.download_button(
                "📑 Download PDF",
                data=pdf_bytes,
                file_name=f"cloudguard_{_slug}.pdf",
                mime="application/pdf",
                use_container_width=True,
                key=f"dl_pdf_{_eid}",
            )
        except Exception as e:
            st.caption(f"PDF unavailable: {e}")




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

    # AWS credentials — always per-session, never from shared server env
    with st.expander("☁️ AWS Credentials", expanded=not bool(st.session_state.get("aws_key_id"))):
        st.caption("Enter your own AWS credentials. These are never stored or logged.")
        aws_key_id = st.text_input("Access Key ID", placeholder="AKIA...", type="password", key="aws_key_id")
        aws_secret = st.text_input("Secret Access Key", placeholder="...", type="password", key="aws_secret_key")
        aws_region = st.text_input("Region", value=st.session_state.get("aws_region_val", "us-east-1"), key="aws_region_val")
        if aws_key_id and aws_secret:
            st.success("AWS credentials set ✓")


    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    preview_mode = st.toggle(
        "⚡ UI Preview Mode",
        value=False,
        help="Loads a mock result instantly — no API call. Great for UI iteration."
    )
    if preview_mode:
        st.caption("Preview active — no API calls will be made.")

    # Activity log — shows last 5 events regardless of success or error
    activity = st.session_state.get("activity", [])
    if activity:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📋 Recent Activity", expanded=True):
            for entry in reversed(activity[-5:]):
                st.caption(f"{entry['icon']} {entry['time']} — {entry['message']}")
            if st.button("Clear", key="clear_activity"):
                st.session_state["activity"] = []
                st.rerun()


st.markdown("""
<div class="cg-header">
  <h1>🛡️ CloudGuard AI</h1>
  <p>AWS Security Hub Misconfiguration Analyzer</p>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["💾 Manual Input", "☁️ Live AWS Findings", "📊 Risk Profile"])


with tab1:
    finding = None
    finding_source = None

    input_method = st.radio(
        "Input method",
        ["📂 Sample finding", "📋 Paste JSON", "📁 Upload .json file"],
        index=0,
        horizontal=True,
    )
    st.markdown("<br>", unsafe_allow_html=True)

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
                        add_activity(f"Preview: {finding.get('Title','Finding')[:50]}")
                        st.session_state[cache_key] = result
                        st.rerun()
                    elif not sidebar_key:
                        st.error("No API key found. Set ANTHROPIC_API_KEY or enter in the sidebar.")
                    else:
                        if check_rate_limit():
                            st.stop()
                        with st.spinner("Analyzing finding..."):
                            result = analyze_finding(finding, api_key=sidebar_key)
                        if "error" in result:
                            msg = result['error']
                            log.error(f"Analysis error shown in UI: {msg}")
                            add_activity(msg, level="error")
                            st.error(f"Analysis failed: {msg}")
                        else:
                            add_activity(f"Analyzed: {finding.get('Title','Finding')[:50]}")
                            from memory_store import store as mem_store
                            mem_store(finding, result)
                            st.session_state[cache_key] = result
                            st.rerun()
    else:
        st.markdown("""
        <div style="text-align:center; padding: 60px 20px;">
          <div style="font-size: 3rem; margin-bottom: 16px;">🛡️</div>
          <div style="font-size: 1.1rem; font-weight: 600; color: #475569;">Select a finding to get started</div>
          <div style="font-size: 0.88rem; margin-top: 8px; color: #334155;">Choose from the sidebar or paste your own JSON</div>
        </div>
        """, unsafe_allow_html=True)


with tab2:
    st.markdown('<div class="section-header">Live AWS Security Hub</div>', unsafe_allow_html=True)

    aws_key = st.session_state.get("aws_key_id", "")
    aws_secret = st.session_state.get("aws_secret_key", "")
    aws_region = st.session_state.get("aws_region_val", "us-east-1")

    # In preview mode, read directly from .env file (bypasses os.environ)
    if preview_mode:
        from dotenv import dotenv_values
        _dot = dotenv_values(".env")
        if not aws_key:
            aws_key = _dot.get("AWS_ACCESS_KEY_ID", "")
        if not aws_secret:
            aws_secret = _dot.get("AWS_SECRET_ACCESS_KEY", "")
        if not aws_region or aws_region == "us-east-1":
            aws_region = _dot.get("AWS_DEFAULT_REGION", "us-east-1")
        if aws_key:
            st.caption("🔑 Using AWS credentials from .env file")


    if not aws_key or not aws_secret:
        st.warning("⚠️ Enter your AWS credentials in the sidebar to connect to Security Hub.")
    else:
        # Connection status — invalidate cache if credentials changed
        conn_cache_key = f"aws_conn_{aws_key[:8]}"
        if conn_cache_key not in st.session_state:
            with st.spinner("Connecting to AWS..."):
                st.session_state[conn_cache_key] = verify_aws_connection(aws_key, aws_secret, aws_region)

        conn = st.session_state[conn_cache_key]
        if not conn["ok"]:
            st.error(f"AWS connection failed: {conn['error']}")
        else:
            st.success(f"✓ Connected | Account: {conn['account_id']} | Region: {conn['region']}")

            # Controls row
            ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 2, 1])
            with ctrl_col1:
                sev_filter = st.multiselect(
                    "Severity filter",
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=["CRITICAL", "HIGH"],
                )
            with ctrl_col2:
                max_results = st.slider("Max findings", 5, 100, 25)
            with ctrl_col3:
                refresh = st.button("🔄 Refresh", use_container_width=True)

            if refresh:
                st.session_state.pop("live_findings", None)
                st.session_state.pop("aws_summary", None)

            # Fetch findings
            if "live_findings" not in st.session_state:
                with st.spinner("Fetching findings from Security Hub..."):
                    st.session_state["live_findings"] = get_findings(
                        aws_key, aws_secret,
                        severity_filter=sev_filter or None,
                        max_results=max_results,
                        region=aws_region,
                    )
                    st.session_state["aws_summary"] = get_summary(aws_key, aws_secret, aws_region)


            findings = st.session_state.get("live_findings", [])
            summary = st.session_state.get("aws_summary", {})

            # Summary metric cards
            st.markdown('<div class="section-header">Posture Overview</div>', unsafe_allow_html=True)
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("🔴 Critical", summary.get("CRITICAL", 0))
            m2.metric("🟠 High", summary.get("HIGH", 0))
            m3.metric("🟡 Medium", summary.get("MEDIUM", 0))
            m4.metric("🟢 Low", summary.get("LOW", 0))

            if not findings:
                st.info("No findings match your current filter.")
            else:
                st.markdown(f'<div class="section-header">{len(findings)} Findings</div>', unsafe_allow_html=True)

                SEV_COLOR = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                for idx, f in enumerate(findings):
                    sev = f.get("Severity", {}).get("Label", "UNKNOWN")
                    title = f.get("Title", "Unknown")
                    resource = (f.get("Resources") or [{}])[0].get("Id", "—")[-60:]
                    fid = f.get("Id", str(idx))

                    with st.expander(f"{SEV_COLOR.get(sev, '')} {sev} — {title}", expanded=False):
                        st.caption(f"Resource: `{resource}`")
                        cache_key = f"live_{fid}"

                        if cache_key in st.session_state:
                            render_analysis(f, st.session_state[cache_key])
                            st.caption("⚡ Cached")
                        else:
                            use_agent = sev in ("CRITICAL", "HIGH")
                            label = "🤖 Agent Analyze" if use_agent else "🔍 Analyze"
                            if st.button(label, key=f"btn_{idx}", type="primary"):
                                if not sidebar_key:
                                    st.error("No API key in sidebar.")
                                else:
                                    if check_rate_limit():
                                        st.stop()
                                    tip = "Running agent with CVE + compliance tools..." if use_agent else "Analyzing..."
                                    with st.spinner(tip):
                                        fn = analyze_with_agent if use_agent else analyze_finding
                                        result = fn(f, api_key=sidebar_key)
                                    if "error" in result:
                                        add_activity(result["error"], level="error")
                                        st.error(result["error"])
                                    else:
                                        add_activity(f"{'Agent' if use_agent else 'Analyzed'}: {title[:40]}")
                                        from memory_store import store as mem_store
                                        mem_store(f, result)
                                        st.session_state[cache_key] = result
                                        st.rerun()


with tab3:
    st.markdown('<div class="section-header">Org Risk Intelligence</div>', unsafe_allow_html=True)

    mem_count = memory_count()

    if mem_count == 0:
        st.info("🧠 No findings in memory yet. Analyse some findings in the other tabs to build your risk profile.")
    else:
        if st.button("🔄 Refresh Profile", key="refresh_profile"):
            st.session_state.pop("risk_profile", None)

        if "risk_profile" not in st.session_state:
            with st.spinner("Computing risk profile..."):
                st.session_state["risk_profile"] = get_profile()

        profile = st.session_state["risk_profile"]

        # Risk score card
        score = profile["score"]
        label = profile["label"]
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,#0d1b40,#0a1628);
                    border:1px solid rgba(99,179,255,0.2);border-radius:16px;
                    padding:28px 36px;margin-bottom:20px;text-align:center;">
          <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:#4a6fa5;margin-bottom:8px;">
            Org Risk Score
          </div>
          <div style="font-size:4rem;font-weight:800;
                      background:linear-gradient(90deg,#63b3ff,#a78bfa);
                      -webkit-background-clip:text;-webkit-text-fill-color:transparent;">
            {score}
          </div>
          <div style="font-size:1.1rem;font-weight:600;color:#e2e8f0;margin-top:4px;">{label}</div>
          <div style="font-size:0.85rem;color:#64748b;margin-top:8px;">{mem_count} findings in memory</div>
        </div>
        """, unsafe_allow_html=True)

        st.caption(profile["trend_hint"])

        # Severity breakdown
        st.markdown('<div class="section-header">Severity Breakdown</div>', unsafe_allow_html=True)
        bd = profile["breakdown"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔴 Critical", bd["CRITICAL"])
        c2.metric("🟠 High",     bd["HIGH"])
        c3.metric("🟡 Medium",   bd["MEDIUM"])
        c4.metric("🟢 Low",      bd["LOW"])

        # Top recurring issues
        if profile["top_issues"]:
            st.markdown('<div class="section-header">Top Recurring Issues</div>', unsafe_allow_html=True)
            for i, issue in enumerate(profile["top_issues"], 1):
                bar_pct = min(int((issue["count"] / profile["total"]) * 100), 100)
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
                  <span style="color:#64748b;width:18px;text-align:right;font-size:0.8rem;">{i}</span>
                  <div style="flex:1;">
                    <div style="font-size:0.88rem;color:#e2e8f0;margin-bottom:4px;">{issue['title'][:80]}</div>
                    <div style="height:4px;background:rgba(99,179,255,0.1);border-radius:2px;">
                      <div style="width:{bar_pct}%;height:100%;background:linear-gradient(90deg,#63b3ff,#a78bfa);border-radius:2px;"></div>
                    </div>
                  </div>
                  <span style="color:#63b3ff;font-weight:700;font-size:0.85rem;min-width:24px;">{issue['count']}</span>
                </div>
                """, unsafe_allow_html=True)

        # Finding history with RAG re-analysis
        from memory_store import get_all as get_all_findings
        st.markdown('<div class="section-header">Finding History</div>', unsafe_allow_html=True)
        all_findings_meta = get_all_findings(limit=100)

        if all_findings_meta:
            SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            for idx, meta in enumerate(reversed(all_findings_meta[:50])):
                sev = meta.get("severity", "LOW")
                title = meta.get("title", "Unknown")[:70]
                stored_at = meta.get("stored_at", "")[:10]

                with st.expander(f"{SEV_ICON.get(sev,'')} {sev} — {title}  ·  {stored_at}", expanded=False):
                    try:
                        past_result = json.loads(meta.get("analysis_json", "{}"))
                        if past_result:
                            st.markdown(f"**TL;DR:** {past_result.get('tldr','—')}")
                            st.markdown(f"**Priority:** {past_result.get('priority','—')}")
                            st.markdown(f"**Plain English:** {past_result.get('plain_english','—')}")
                    except Exception:
                        st.caption("Analysis not available.")

                    rag_key = f"rag_history_{idx}"
                    if rag_key in st.session_state:
                        render_analysis({}, st.session_state[rag_key])
                    elif sidebar_key:
                        if st.button("🧠 Re-analyse with RAG", key=f"rag_btn_{idx}"):
                            try:
                                finding_stub = {"Title": title, "Severity": {"Label": sev}}
                                with st.spinner("Running RAG analysis..."):
                                    rag_result = analyze_with_rag(finding_stub, api_key=sidebar_key)
                                if "error" not in rag_result:
                                    st.session_state[rag_key] = rag_result
                                    add_activity(f"RAG re-analysis: {title[:40]}")
                                    st.rerun()
                                else:
                                    st.error(rag_result["error"])
                            except Exception as e:
                                st.error(str(e))
