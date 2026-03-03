#!/usr/bin/env bash
# Launch CloudGuard AI Streamlit application
cd "$(dirname "$0")"
./venv/bin/streamlit run app.py "$@"
