# 🛡️ CloudGuard AI

**AI-powered AWS Security Hub misconfiguration analyzer powered by Claude.**

CloudGuard AI transforms raw Security Hub findings into plain-English risk reports with actionable remediation steps, authoritative citations, compliance mapping, CVE lookups, and an org-level risk profile — all in a Streamlit UI.

🔗 **Live demo (MVP 1):** [cloudguard.streamlit.app](https://cloudguard.streamlit.app)

---

## Features

### MVP 1 — Manual Analyzer (public)
- Paste, upload, or select sample Security Hub findings
- Claude-powered analysis: TL;DR, business impact, step-by-step remediation, compliance tags
- **Authoritative citations** linking each fix to AWS docs, NVD CVEs, CIS benchmarks, and NIST controls
- Export reports as **Markdown** (including citations)
- Rate limited (5 analyses/hour per session)

### MVP 2 — Live AWS Integration
- Connect to your AWS account via sidebar credentials
- Live pull from **Security Hub** with severity filtering and pagination
- **Agent mode** for HIGH/CRITICAL findings: chains CVE lookup (with NVD URLs), AWS docs, and compliance checks via Claude tool-use
- Smart resource labeling — hides generic account-level ARNs, shows only meaningful resource names
- Per-session credential isolation — your AWS keys never touch the server

### MVP 3 — Risk Intelligence
- **RAG analysis** — retrieves similar past findings before calling Claude for richer, org-aware reports
- **Risk Profile tab** — 0–100 org risk score using weighted-average severity, severity breakdown, top recurring issues, finding history
- Local vector memory (`sentence-transformers` + cosine similarity) — no cloud vector DB required
- Every successful analysis auto-stores to memory for future RAG enrichment

---

## Architecture

```
cloudguard/
├── app.py                 # Main Streamlit app (3 tabs)
├── analyzer.py            # Core Claude API call → structured JSON with citations
├── agent_analyzer.py      # Claude tool-use loop for HIGH/CRITICAL
├── aws_connector.py       # boto3 Security Hub client
├── tools.py               # Agent tools: CVE lookup (with NVD URLs), AWS docs, compliance
├── rag_analyzer.py        # RAG-enhanced analysis using past findings
├── memory_store.py        # JSON vector store (sentence-transformers)
├── risk_profiler.py       # Org risk score (weighted-average) + trend analysis
├── exporter.py            # Markdown report generation with citations
├── logger.py              # Rotating file + console logger
├── run.sh                 # Launch script (uses venv)
├── mvp1/                  # Standalone public deployment (Tab 1 only)
├── sample_findings/       # 5 real-world Security Hub finding JSONs
└── tests/                 # pytest unit tests (20+ tests)
```

---

## Quickstart

### Prerequisites
- Python 3.11+
- Anthropic API key ([console.anthropic.com](https://console.anthropic.com))
- *(Optional)* AWS account with Security Hub enabled

### Setup

```bash
git clone https://github.com/samadmd786/cloudguard.git
cd cloudguard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file (see `.env.example`):
```env
ANTHROPIC_API_KEY=sk-ant-...
AWS_ACCESS_KEY_ID=AKIA...         # optional — for Tab 2
AWS_SECRET_ACCESS_KEY=...         # optional — for Tab 2
AWS_DEFAULT_REGION=us-east-1
```

Run:
```bash
./run.sh
```

---

## Tabs

| Tab | What it does |
|-----|-------------|
| 💾 Manual Input | Select a sample finding, paste JSON, or upload a file → analyze |
| ☁️ Live AWS Findings | Connect to your AWS account → pull live Security Hub findings → analyze |
| 📊 Risk Profile | Org risk score, top recurring issues, finding history, RAG re-analysis |

---

## AWS Setup (for Tab 2)

1. Enable **Security Hub** in your AWS console
2. Create an IAM user with `AWSSecurityHubReadOnlyAccess` policy
3. Generate access keys
4. Paste them into the **☁️ AWS Credentials** sidebar expander — they're session-only, never stored

---

## Running Tests

```bash
./venv/bin/python3 -m pytest tests/ -v
```

Tests cover `analyzer.py`, `aws_connector.py`, `agent_analyzer.py`, `exporter.py`, `risk_profiler.py`, `memory_store.py`, and `tools.py` using mocked boto3 and Anthropic clients.

---

## Deployment

The `mvp1/` folder is a self-contained version deployed to Streamlit Cloud at [cloudguard.streamlit.app](https://cloudguard.streamlit.app). It uses only the Anthropic API (no AWS credentials required) and applies a 5/hour rate limit.

To deploy your own:
1. Fork this repo
2. Connect to [share.streamlit.io](https://share.streamlit.io)
3. Set main file to `mvp1/app.py`
4. Add `ANTHROPIC_API_KEY` to Streamlit secrets

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| UI | Streamlit |
| LLM | Claude (Anthropic) via `anthropic` SDK |
| AWS | boto3 + Security Hub |
| Memory | sentence-transformers + JSON vector store |
| Tests | pytest + pytest-mock |

---