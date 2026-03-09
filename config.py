"""
Centralized configuration loader.

Resolves config values from multiple sources in priority order:
  1. os.environ (shell exports, CI/CD, Docker)
  2. .env file  (local development via python-dotenv)
  3. st.secrets (Streamlit Cloud deployments)

All modules should use `get_secret()` instead of accessing
os.environ or st.secrets directly.
"""
import os
from dotenv import load_dotenv
from logger import get_logger

log = get_logger(__name__)

# Load .env once at import time; existing env vars take precedence
load_dotenv(override=False)

# Placeholder prefixes that should be treated as "not set"
_PLACEHOLDER_MARKERS = ("your-", "your_", "<", "example", "changeme", "replace", "sk-ant-your")


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like a template placeholder."""
    return any(value.lower().startswith(m) for m in _PLACEHOLDER_MARKERS)


def get_secret(name: str, default: str = "") -> str:
    """
    Retrieve a configuration secret from the environment or Streamlit secrets.

    Lookup order:
      1. os.environ  (includes values loaded from .env by python-dotenv)
      2. st.secrets  (Streamlit Cloud / secrets.toml)

    Placeholder values (e.g. 'your-key-here') are treated as missing.

    Args:
        name (str):    The environment variable / secret name.
        default (str): Fallback value if the secret is not found anywhere.

    Returns:
        str: The resolved value, or `default` if not found.
    """
    # 1. os.environ (already includes .env via load_dotenv)
    val = os.environ.get(name, "")
    if val and not _is_placeholder(val):
        return val

    # 2. Streamlit secrets (works on Streamlit Cloud or with secrets.toml)
    try:
        import streamlit as st
        val = st.secrets.get(name, "")
        if val and not _is_placeholder(val):
            return val
    except Exception:
        pass

    return default
