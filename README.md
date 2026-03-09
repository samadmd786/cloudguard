# 🛡️ CloudGuard AI

**AI-powered AWS Security Hub misconfiguration analyzer powered by Claude.**

CloudGuard AI transforms raw Security Hub findings into plain-English risk reports with actionable remediation steps, authoritative citations, compliance mapping, CVE lookups, and an org-level risk profile — all in a Streamlit UI.

🔗 **Live demo:** [cloudguard.streamlit.app](https://cloudguard.streamlit.app/)

---

## Features

### Manual Analysis
- Paste, upload, or select sample Security Hub findings
- Claude-powered analysis: TL;DR, business impact, step-by-step remediation, compliance tags
- **Authoritative citations** linking each fix to AWS docs, NVD CVEs, CIS benchmarks, and NIST controls
- Export reports as **Markdown** (including citations)
- Rate limited (20 analyses/hour per session)

### Live AWS Integration
- Connect to your AWS account — enter credentials manually or toggle **🔑 Use configured AWS credentials**
- Live pull from **Security Hub** with severity filtering and pagination
- **Agent mode** for HIGH/CRITICAL findings: chains CVE lookup (with NVD URLs), AWS docs, and compliance checks via Claude tool-use
- Smart resource labeling — hides generic account-level ARNs, shows only meaningful resource names
- Per-session credential isolation — your AWS keys never touch the server

### Risk Intelligence
- **RAG analysis** — retrieves similar past findings before calling Claude for richer, org-aware reports
- **Risk Profile** — 0–100 org risk score using weighted-average severity with confidence scaling, severity breakdown, top recurring issues, finding history
- Local vector memory (`sentence-transformers` + cosine similarity) — no cloud vector DB required
- Every successful analysis auto-stores to memory for future RAG enrichment

---

## Architecture

```
cloudguard/
├── app.py                 # Main Streamlit app (Home + 3 tabs)
├── cloudguard/            # Core backend package
│   ├── __init__.py        # Package initialization
│   ├── analyzer.py        # Core Claude API call → structured JSON with citations
│   ├── agent_analyzer.py  # Claude tool-use loop for HIGH/CRITICAL
│   ├── aws_connector.py   # boto3 Security Hub client
│   ├── tools.py           # Agent tools: CVE lookup (NVD), AWS docs, compliance
│   ├── rag_analyzer.py    # RAG-enhanced analysis using past findings
│   ├── memory_store.py    # JSON vector store (sentence-transformers)
│   ├── risk_profiler.py   # Org risk score (weighted-average) + trend analysis
│   ├── config.py          # Centralized secret loader (.env → st.secrets)
│   ├── exporter.py        # Markdown report generation with citations
│   └── logger.py          # Rotating file + console logger
├── run.sh                 # Launch script (uses venv)
├── sample_findings/       # 5 real-world Security Hub finding JSONs
├── mvp1/                  # Earlier standalone version (see mvp1/README.md)
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

Secrets can be provided in any of three ways (checked in this order):

1. **Shell environment variables** (CI/CD, Docker)
2. **`.env` file** — copy `.env.example` and fill in values
3. **Streamlit secrets** — `.streamlit/secrets.toml` for Streamlit Cloud

```env
ANTHROPIC_API_KEY=sk-ant-...
AWS_ACCESS_KEY_ID=AKIA...         # optional — for Live AWS tab
AWS_SECRET_ACCESS_KEY=...         # optional — for Live AWS tab
AWS_DEFAULT_REGION=us-east-1
```

Run:
```bash
./run.sh
```

---

## Pages

| Page | What it does |
|------|-------------|
| 🏠 Home | Landing page — overview, Get Started cards, feature highlights, how-it-works |
| 💾 Manual Input | Select a sample finding, paste JSON, or upload a file → analyze |
| ☁️ Live AWS Findings | Connect to your AWS account → pull live Security Hub findings → analyze |
| 📊 Risk Profile | Org risk score, top recurring issues, finding history, RAG re-analysis |

---

## AWS Setup (for Live AWS tab)

1. Enable **Security Hub** in your AWS console
2. Create an IAM user with `AWSSecurityHubReadOnlyAccess` policy
3. Generate access keys
4. Paste them into the **☁️ AWS Credentials** expander — session-only, never stored

---

## Running Tests

```bash
./venv/bin/python3 -m pytest tests/ -v
```

Tests cover `analyzer.py`, `aws_connector.py`, `agent_analyzer.py`, `exporter.py`, `risk_profiler.py`, `memory_store.py`, and `tools.py` using mocked boto3 and Anthropic clients.

---

## Deployment

The full application is deployed to Streamlit Cloud at [cloudguard.streamlit.app](https://cloudguard.streamlit.app/).

To deploy your own:
1. Fork this repo
2. Connect to [share.streamlit.io](https://share.streamlit.io)
3. Set main file to `app.py`
4. Add `ANTHROPIC_API_KEY` to Streamlit secrets
5. *(Optional)* Add AWS credentials to Streamlit secrets for the Live AWS tab

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| UI | Streamlit |
| LLM | Claude 3.5 Sonnet (Anthropic) via `anthropic` SDK |
| Agent | Claude tool-use (ReAct loop) |
| AWS | boto3 + Security Hub |
| RAG | sentence-transformers + JSON vector store |
| Config | python-dotenv + st.secrets |
| Tests | pytest + pytest-mock |

---

## How AI Was Used to Build This Project

AI was a core part of both the **product** and the **development process** for CloudGuard. Below is a detailed breakdown of every significant way AI was leveraged.

### 1. Claude as the Core Analysis Engine

The entire product is built around Claude (Anthropic's LLM). Every Security Hub finding is sent to Claude with a carefully crafted system prompt (`analyzer.py`) that instructs it to return **structured JSON** with specific fields: a TL;DR summary, severity assessment, business impact, step-by-step remediation (including exact AWS CLI commands), compliance tags, priority, and authoritative citations. This isn't just a "summarize this" prompt — it's a constrained, schema-enforced output that the UI can parse and render deterministically.

**Prompt engineering decisions:**
- The system prompt explicitly requests JSON output with named fields, so the Streamlit UI can render each section (impact cards, compliance tags, citation links) without fragile text parsing.
- A `You are a senior AWS security engineer` persona was chosen after testing that it produces more specific remediation steps than a generic analyst persona.
- The prompt includes instructions for citations — Claude must link remediation steps to NVD CVE pages, AWS documentation, and CIS benchmark IDs, which are hyperlinked in the UI.

### 2. Agentic Tool-Use for HIGH/CRITICAL Findings

For the most severe findings, a single Claude call isn't enough. `agent_analyzer.py` implements a **multi-turn ReAct-style agent loop** using Claude's native tool-use capabilities:

1. Claude receives the finding and a set of tool schemas (`tools.py`)
2. Instead of immediately answering, Claude decides which tools to call — typically:
   - `lookup_cves` — queries the NVD API for related CVEs with CVSS scores
   - `fetch_aws_remediation` — retrieves the official AWS docs URL for the specific Security Hub control
   - `check_compliance` — maps the finding to CIS, PCI DSS, SOC 2, NIST 800-53, and ISO 27001 controls
3. Tool results are fed back into the conversation
4. Claude synthesizes everything into the same structured JSON, but now enriched with real CVE IDs, CVSS scores, and authoritative URLs

This agent loop runs up to 5 rounds. The key design decision was letting Claude choose which tools to call and in what order — for MEDIUM/LOW findings, it only calls `check_compliance` (saving latency and API cost), while for CRITICAL findings it calls all three tools.

### 3. RAG (Retrieval-Augmented Generation)

`rag_analyzer.py` implements RAG to give Claude organizational context:

- Every analyzed finding is stored in a local vector store (`memory_store.py`) using `sentence-transformers` to generate embeddings
- When a new finding arrives, the system retrieves the top-k most similar past findings and their analyses via cosine similarity
- These are injected into Claude's prompt as "Previously analyzed similar findings in your organization"
- Claude can then say things like "This is the third S3 public access issue in your environment — consider a preventive SCP" rather than treating each finding in isolation

This creates an **organizational knowledge base** that improves over time. The more findings you analyze, the richer the context Claude receives.

### 4. AI-Assisted Development Process

The development of CloudGuard itself was heavily AI-assisted:

- **Architecture design:** The 3-tier analysis routing (simple → agent → RAG) was designed iteratively with AI assistance, debating tradeoffs between latency, cost, and analysis depth
- **System prompt iteration:** Multiple rounds of prompt engineering were done to get Claude to reliably output valid JSON with the exact schema needed, handle edge cases (empty fields, unknown severities), and include actionable CLI commands
- **UI/UX development:** The landing page layout, dark theme CSS, card components, and session-state routing were built with AI pair-programming, iterating on visual design and Streamlit patterns
- **Bug fixes and refactoring:** AI was used to debug issues like truncated analysis JSON in the memory store, misleading risk scores from small sample sizes, and inconsistent environment variable handling — each fix was identified and implemented through AI-assisted code review
- **Centralized configuration:** The `config.py` module (`.env` → `st.secrets` fallback chain with placeholder detection) was designed and implemented with AI assistance to handle the complexity of multiple secret sources
- **Test generation:** The 20+ pytest tests covering all modules were scaffolded with AI, including mock patterns for boto3 and the Anthropic SDK
- **Risk score formula:** The confidence-scaled risk scoring formula (`1 - 1/(1 + total*0.5)`) was developed with AI to prevent misleading scores from small sample sizes — a single CRITICAL finding now shows a dampened score with a "Low confidence" indicator

### 5. Key AI Techniques Demonstrated

| Technique | Where it's used |
|-----------|----------------|
| **Structured output prompting** | `analyzer.py` — Claude returns JSON matching a predefined schema |
| **Tool-use / function calling** | `agent_analyzer.py` — Claude autonomously calls CVE, docs, and compliance tools |
| **Multi-turn agent loop (ReAct)** | `agent_analyzer.py` — iterative tool→result→tool cycles up to 5 rounds |
| **RAG** | `rag_analyzer.py` — past findings enrichment via vector similarity search |
| **Embedding-based retrieval** | `memory_store.py` — sentence-transformers embeddings + cosine similarity |
| **Prompt engineering** | System prompts designed for persona, schema enforcement, and citation generation |
| **AI pair-programming** | Used throughout development for architecture, debugging, and UI design |

