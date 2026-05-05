# 🛡️ CloudGuard AI

**AI-powered AWS Security Hub misconfiguration analyzer powered by Groq + Llama 3.3 70B.**

CloudGuard AI transforms raw Security Hub findings into plain-English risk reports with actionable remediation steps, authoritative citations, compliance mapping, CVE lookups, and an org-level risk profile — all in a Streamlit UI.

🔗 **Live demo:** [cloudguard.streamlit.app](https://cloudguard.streamlit.app/)

---

## Features

### Manual Analysis
- Paste, upload, or select sample Security Hub findings
- AI-powered analysis: TL;DR, business impact, step-by-step remediation, compliance tags
- **Authoritative citations** linking each fix to AWS docs, NVD CVEs, CIS benchmarks, and NIST controls
- Export reports as **Markdown** (including citations)
- Rate limited (20 analyses/hour per session)

### Live AWS Integration
- Connect to your AWS account — enter credentials manually or toggle **🔑 Use configured AWS credentials**
- Live pull from **Security Hub** with severity filtering and pagination
- **Agent mode** for HIGH/CRITICAL findings: pre-fetches CVE data (NVD), AWS docs, and compliance controls, then injects them as enrichment context into the LLM prompt
- Smart resource labeling — hides generic account-level ARNs, shows only meaningful resource names
- Per-session credential isolation — your AWS keys never touch the server

### Risk Intelligence
- **RAG analysis** — retrieves similar past findings before calling the LLM for richer, org-aware reports
- **Risk Profile** — 0–100 org risk score using weighted-average severity with confidence scaling, severity breakdown, top recurring issues, finding history
- Local vector memory (`sentence-transformers` + cosine similarity) — no cloud vector DB required
- Every successful analysis auto-stores to memory for future RAG enrichment

### Security & Stability
- **XSS Protection**: All untrusted outputs from LLMs and AWS are sanitized and HTML-escaped before being rendered in the UI.
- **Robust Exception Handling**: Comprehensive fallback mechanisms for malformed JSON, file reading permissions, rate limits, and unreachable endpoints.
- **Thread-safe Logging**: Rotating file logging is safeguarded with thread locks to prevent race conditions during high-concurrency access.
- **Data Validation**: Strict parsing checks on API inputs, CVE outputs, and array indexing to prevent runtime errors.

---

## Architecture

```
cloudguard/
├── app.py                 # Main Streamlit app (Home + 3 tabs)
├── cloudguard/            # Core backend package
│   ├── __init__.py        # Package initialization
│   ├── nvidia_client.py   # LLM client (Groq API — OpenAI-compatible)
│   ├── analyzer.py        # Core LLM call → structured JSON with citations
│   ├── agent_analyzer.py  # Enriched analysis for HIGH/CRITICAL findings
│   ├── aws_connector.py   # boto3 Security Hub client
│   ├── tools.py           # Enrichment tools: CVE lookup (NVD), AWS docs, compliance
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
- Groq API key — free at [console.groq.com](https://console.groq.com) (no credit card required)
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
GROQ_API_KEY=gsk_...             # required — get free at console.groq.com
AWS_ACCESS_KEY_ID=AKIA...        # optional — for Live AWS tab
AWS_SECRET_ACCESS_KEY=...        # optional — for Live AWS tab
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

Tests cover `analyzer.py`, `aws_connector.py`, `agent_analyzer.py`, `exporter.py`, `risk_profiler.py`, `memory_store.py`, and `tools.py` using mocked boto3 and Groq clients.

---

## Deployment

To deploy your own:
1. Fork this repo
2. Connect to [share.streamlit.io](https://share.streamlit.io)
3. Set main file to `app.py`
4. Add `GROQ_API_KEY` to Streamlit secrets
5. *(Optional)* Add AWS credentials to Streamlit secrets for the Live AWS tab

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| UI | Streamlit |
| LLM | Llama 3.3 70B Versatile via [Groq](https://groq.com) (free tier) |
| Agent | Pre-fetched tool enrichment injected as prompt context |
| AWS | boto3 + Security Hub |
| RAG | sentence-transformers + JSON vector store |
| Config | python-dotenv + st.secrets |
| Tests | pytest + pytest-mock |

---

## How AI Was Used to Build This Project

AI was a core part of both the **product** and the **development process** for CloudGuard. Below is a detailed breakdown of every significant way AI was leveraged.

### 1. LLM as the Core Analysis Engine

Every Security Hub finding is sent to **Llama 3.3 70B** (via Groq) with a carefully crafted system prompt (`analyzer.py`) that instructs it to return **structured JSON** with specific fields: a TL;DR summary, severity assessment, business impact, step-by-step remediation (including exact AWS CLI commands), compliance tags, priority, and authoritative citations. This isn't just a "summarize this" prompt — it's a constrained, schema-enforced output that the UI can parse and render deterministically.

**Prompt engineering decisions:**
- The system prompt explicitly requests JSON output with named fields, so the Streamlit UI can render each section (impact cards, compliance tags, citation links) without fragile text parsing.
- A `You are a senior AWS security engineer` persona was chosen after testing that it produces more specific remediation steps than a generic analyst persona.
- The prompt includes instructions for citations — the model must link remediation steps to NVD CVE pages, AWS documentation, and CIS benchmark IDs, which are hyperlinked in the UI.

### 2. Enriched Agent Analysis for HIGH/CRITICAL Findings

For the most severe findings, a single LLM call isn't enough. `agent_analyzer.py` implements a **pre-fetch enrichment pipeline**:

1. Tool functions in `tools.py` are called **locally** (no LLM needed) to gather:
   - `lookup_cves` — queries the NVD API for related CVEs with CVSS scores and URLs
   - `fetch_aws_remediation` — retrieves the official AWS docs URL for the specific Security Hub control
   - `check_compliance` — maps the finding to CIS, PCI DSS, SOC 2, NIST 800-53, and ISO 27001 controls
2. The results are formatted as structured context and **injected into the prompt**
3. A single LLM call synthesizes everything into enriched JSON with real CVE IDs, CVSS scores, and authoritative URLs

For MEDIUM/LOW findings it falls back to the standard `analyze_finding` path (saving latency). The key design decision was keeping tool execution local — this avoids the need for function-calling API support from the model, making the architecture compatible with any capable chat model.

### 3. RAG (Retrieval-Augmented Generation)

`rag_analyzer.py` implements RAG to give the LLM organizational context:

- Every analyzed finding is stored in a local vector store (`memory_store.py`) using `sentence-transformers` to generate embeddings
- When a new finding arrives, the system retrieves the top-k most similar past findings and their analyses via cosine similarity
- These are injected into the LLM's prompt as "Previously analyzed similar findings in your organization"
- The model can then say things like "This is the third S3 public access issue in your environment — consider a preventive SCP" rather than treating each finding in isolation

This creates an **organizational knowledge base** that improves over time. The more findings you analyze, the richer the context the LLM receives.

### 4. AI-Assisted Development Process

The development of CloudGuard itself was heavily AI-assisted:

- **Architecture design:** The 3-tier analysis routing (simple → enriched agent → RAG) was designed iteratively with AI assistance, debating tradeoffs between latency, cost, and analysis depth
- **System prompt iteration:** Multiple rounds of prompt engineering were done to get the LLM to reliably output valid JSON with the exact schema needed, handle edge cases, and include actionable CLI commands
- **UI/UX development:** The landing page layout, dark theme CSS, card components, and session-state routing were built with AI pair-programming
- **Bug fixes and refactoring:** AI was used to debug issues like truncated analysis JSON, misleading risk scores from small sample sizes, and inconsistent environment variable handling
- **Centralized configuration:** The `config.py` module (`.env` → `st.secrets` fallback chain with placeholder detection) was designed and implemented with AI assistance
- **Test generation:** The 20+ pytest tests covering all modules were scaffolded with AI, including mock patterns for boto3 and the Groq client
- **Risk score formula:** The confidence-scaled risk scoring formula (`1 - 1/(1 + total*0.5)`) was developed with AI to prevent misleading scores from small sample sizes

### 5. Key AI Techniques Demonstrated

| Technique | Where it's used |
|-----------|----------------|
| **Structured output prompting** | `analyzer.py` — LLM returns JSON matching a predefined schema |
| **Prompt-based tool enrichment** | `agent_analyzer.py` — CVE, docs, and compliance data injected as context |
| **RAG** | `rag_analyzer.py` — past findings enrichment via vector similarity search |
| **Embedding-based retrieval** | `memory_store.py` — sentence-transformers embeddings + cosine similarity |
| **Prompt engineering** | System prompts designed for persona, schema enforcement, and citation generation |
| **AI pair-programming** | Used throughout development for architecture, debugging, and UI design |
