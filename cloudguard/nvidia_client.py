"""
LLM API Client (Groq).

Thin wrapper around the Groq inference endpoint
(https://api.groq.com/openai/v1/chat/completions).

Groq uses LPU (Language Processing Unit) hardware for extremely fast inference —
typically under 2 seconds even for 70B parameter models. The API is fully
OpenAI-compatible and has a generous free tier (no credit card required).

This module provides:
  - `nvidia_chat()` — single-shot, returns the full assistant text string
    (name kept for backward compatibility with all analyzer imports)
  - `NVIDIA_MODEL`  — the model name used across all analyzers
  - `NVIDIA_INVOKE_URL` — the API endpoint
"""
import requests
from cloudguard.logger import get_logger

log = get_logger(__name__)

NVIDIA_INVOKE_URL = "https://api.groq.com/openai/v1/chat/completions"
NVIDIA_MODEL = "llama-3.3-70b-versatile"


def nvidia_chat(
    messages: list[dict],
    api_key: str,
    system_prompt: str = "",
    max_tokens: int = 4096,
    temperature: float = 0.7,
    top_p: float = 0.95,
) -> str:
    """
    Send a chat request to Groq and return the full assistant text.

    Uses non-streaming JSON mode for simplicity and reliability.

    Args:
        messages (list[dict]):  Conversation turns, each {"role":…, "content":…}.
        api_key (str):          Groq API key (Bearer token).
        system_prompt (str):    Optional system-level instruction prepended to the
                                messages list as a "system" role turn.
        max_tokens (int):       Maximum number of tokens to generate.
        temperature (float):    Sampling temperature.
        top_p (float):          Nucleus-sampling probability.

    Returns:
        str: The full assistant response text.

    Raises:
        RuntimeError: On non-200 HTTP responses.
    """
    all_messages = []
    if system_prompt:
        all_messages.append({"role": "system", "content": system_prompt})
    all_messages.extend(messages)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": NVIDIA_MODEL,
        "messages": all_messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "stream": False,
    }

    log.debug(f"Groq request | model={NVIDIA_MODEL} messages={len(all_messages)}")

    response = requests.post(
        NVIDIA_INVOKE_URL,
        headers=headers,
        json=payload,
        timeout=60,   # Groq is fast — 60s is generous
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Groq API error {response.status_code}: {response.text[:400]}"
        )

    return response.json()["choices"][0]["message"]["content"]
