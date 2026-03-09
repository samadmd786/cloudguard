# 🛡️ CloudGuard AI — MVP 1

**Standalone manual analyzer — the first milestone of [CloudGuard AI](../).**

This folder contains an earlier, self-contained version of CloudGuard that only requires an Anthropic API key (no AWS credentials). It was the initial public deployment before the full app replaced it.

---

## What MVP 1 does

- Paste, upload, or select a sample AWS Security Hub JSON finding
- Claude analyzes the finding and returns a structured report:
  - **TL;DR** summary
  - **Severity** and **priority** assessment
  - **Business impact** analysis
  - **Step-by-step remediation** with AWS CLI commands
  - **Compliance tags** (CIS, PCI DSS, SOC 2, NIST, ISO 27001)
  - **Authoritative citations** linking to AWS docs, NVD CVEs, and CIS benchmarks
- Export the report as **Markdown**
- Rate limited to 5 analyses/hour per session

---

## Files

```
mvp1/
├── app.py               # Streamlit UI (single-tab manual input)
├── analyzer.py          # Claude API call → structured JSON
├── logger.py            # Rotating file + console logger
├── requirements.txt     # Minimal dependencies (streamlit, anthropic)
├── sample_findings/     # 5 real-world Security Hub finding JSONs
├── tests/               # Basic unit tests
└── .streamlit/          # Streamlit config + secrets template
```

---

## Running locally

```bash
cd mvp1
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
streamlit run app.py
```

---

## What the full app adds

| Feature | MVP 1 | Full App |
|---------|-------|----------|
| Manual input (paste/upload/sample) | ✅ | ✅ |
| Live AWS Security Hub integration | ❌ | ✅ |
| Agent mode (tool-use for CRITICAL/HIGH) | ❌ | ✅ |
| RAG (past findings enrichment) | ❌ | ✅ |
| Risk Profile (org-wide scoring) | ❌ | ✅ |
| Vector memory store | ❌ | ✅ |
| Centralized config (.env + st.secrets) | ❌ | ✅ |

See the [main README](../) for the full app documentation.
