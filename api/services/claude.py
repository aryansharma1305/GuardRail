"""
claude.py — AI-powered code security analysis with a multi-provider fallback chain.

Provider strategy
-----------------
The MODELS list is tried in order.  For each entry the service:
  1. Builds per-provider headers  (Authorization + any custom headers).
  2. POSTs to the provider's OpenAI-compatible  /chat/completions  endpoint.
  3. On HTTP 429 **or** a provider-level 429 embedded in an HTTP-200 body →
     logs a warning and moves on to the next provider.
  4. On any other error (network, bad JSON, non-200) → aborts the chain and
     returns [].
  5. If every provider is rate-limited → logs an error and returns [].

Providers configured
--------------------
  • OpenRouter  — qwen/qwen3-coder:free          (primary)
  • OpenRouter  — nvidia/nemotron-3-ultra-550b-a55b:free  (fallback 1)
  • Groq        — llama-3.3-70b-versatile        (fallback 2)
  • Google      — gemini-2.0-flash               (fallback 3, OpenAI-compat endpoint)

Environment variables
---------------------
  OPENROUTER_API_KEY  — required for OpenRouter models
  GROQ_API_KEY        — required for Groq models
  GEMINI_API_KEY      — required for Gemini models
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── Model / provider registry ─────────────────────────────────────────────────

def _get_models() -> list[dict[str, Any]]:
    """
    Build the provider chain at *call time* so that os.getenv() is evaluated
    after load_dotenv() has populated the environment — not at module import.
    """
    return [
        {
            "name": "qwen/qwen3-coder:free",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": os.getenv("OPENROUTER_API_KEY"),
            "headers": {
                "HTTP-Referer": "https://guardrail.dev",
                "X-Title": "Guardrail",
            },
        },
        {
            "name": "nvidia/nemotron-3-ultra-550b-a55b:free",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key": os.getenv("OPENROUTER_API_KEY"),
            "headers": {
                "HTTP-Referer": "https://guardrail.dev",
                "X-Title": "Guardrail",
            },
        },
        {
            "name": "llama-3.3-70b-versatile",
            "base_url": "https://api.groq.com/openai/v1",
            "api_key": os.getenv("GROQ_API_KEY"),
            "headers": {},
        },
        {
            "name": "gemini-2.0-flash",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
            "api_key": os.getenv("GEMINI_API_KEY"),
            "headers": {},
        },
    ]

# ── Prompts & regexes ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a security code reviewer.
Analyze the code for security vulnerabilities.

CRITICAL RULES:
- You MUST respond with ONLY a JSON object
- No markdown, no backticks, no explanation
- Start your response with { and end with }
- If you find vulnerabilities, list them all
- This code DEFINITELY has vulnerabilities - find them

Required format:
{"vulnerabilities":[{"id":"VULN-001","title":"vulnerability name","severity":"critical","line":1,"description":"what is wrong","fix":"how to fix","fixed_code":"corrected code"}]}

If no vulnerabilities: {"vulnerabilities":[]}"""

# Strips optional ```json … ``` or ``` … ``` fences from model output
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sanitise_json(raw: str) -> str:
    """Remove accidental markdown code-fences from the model's response."""
    raw = raw.strip()
    match = _CODE_FENCE_RE.search(raw)
    if match:
        return match.group(1).strip()
    return raw


def _build_headers(entry: dict[str, Any]) -> dict[str, str]:
    """
    Construct the full HTTP headers for one provider entry.

    Raises ``EnvironmentError`` when the provider's API key is absent so the
    caller can skip to the next entry rather than sending a broken request.
    """
    api_key: str | None = entry.get("api_key")
    if not api_key:
        provider = entry["base_url"]
        raise EnvironmentError(
            f"API key not set for provider {provider!r} (model: {entry['name']!r}). "
            "Check your .env file."
        )

    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # Merge any provider-specific extra headers (e.g. HTTP-Referer for OpenRouter)
    headers.update(entry.get("headers", {}))
    return headers


def _build_payload(model: str, code: str, language: str) -> dict:
    user_message = (
        f"Find ALL security vulnerabilities in this {language} code.\n"
        "Look for: hardcoded passwords, API keys, SQL injection, XSS, "
        "command injection, insecure practices.\n\n"
        f"Code to analyze:\n{code}\n\n"
        "Respond with JSON only. No markdown. No explanation."
    )
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0,
    }


def _parse_vulnerabilities(raw_content: str) -> list[dict] | None:
    """
    Parse the model's text output into a vulnerability list.

    Returns the list on success, or ``None`` if parsing fails — letting the
    caller decide whether to retry with the next provider or give up.
    """
    logger.info("Raw response: %s", raw_content[:1000])
    cleaned = _sanitise_json(raw_content)
    try:
        parsed: dict = json.loads(cleaned)
        vulns = parsed["vulnerabilities"]
    except json.JSONDecodeError as exc:
        logger.error(
            "Failed to parse model JSON: %s\nRaw (first 500 chars): %.500s",
            exc,
            cleaned,
        )
        return None
    except KeyError:
        logger.error(
            "Model JSON missing 'vulnerabilities' key. Raw: %.500s", cleaned
        )
        return None

    if not isinstance(vulns, list):
        logger.error("'vulnerabilities' is not a list: %r", vulns)
        return None

    return vulns


async def _call_model(
    client: httpx.AsyncClient,
    entry: dict[str, Any],
    code: str,
    language: str,
) -> tuple[list[dict] | None, bool]:
    """
    Make a single request to one provider's  /chat/completions  endpoint.

    Returns
    -------
    (vulnerabilities, rate_limited)
      • vulnerabilities : parsed list, or ``None`` on any failure
      • rate_limited    : ``True`` only when the failure was a 429 (HTTP-level
                          or provider-level 429 embedded in an HTTP-200 body).
                          The caller uses this to decide whether to try the next
                          provider or abort the chain.
    """
    model: str = entry["name"]
    base_url: str = entry["base_url"].rstrip("/")
    url = f"{base_url}/chat/completions"

    # Build headers; skip cleanly when the API key is missing
    try:
        headers = _build_headers(entry)
    except EnvironmentError as exc:
        logger.warning("Skipping model %s — %s", model, exc)
        return None, True  # treat as "not available" → try next

    payload = _build_payload(model, code, language)

    try:
        response = await client.post(url, headers=headers, json=payload)
    except httpx.TimeoutException:
        logger.error("Request timed out (model=%s, url=%s)", model, url)
        return None, False
    except httpx.RequestError as exc:
        logger.error("Network error reaching %s (model=%s): %s", url, model, exc)
        return None, False

    # ── HTTP-level rate limit ──────────────────────────────────────────────
    if response.status_code == 429:
        logger.warning("Model %s is rate-limited (HTTP 429).", model)
        return None, True

    if response.status_code != 200:
        logger.error(
            "HTTP %s from %s (model=%s): %s",
            response.status_code,
            url,
            model,
            response.text[:500],
        )
        return None, False

    # ── Decode body ────────────────────────────────────────────────────────
    try:
        body: dict = response.json()
    except Exception:
        logger.error("Could not decode JSON from %s (model=%s)", url, model)
        return None, False

    # ── Provider-level error embedded in HTTP-200 ──────────────────────────
    # Some providers (e.g. OpenRouter when an upstream is overloaded) return
    # HTTP 200 with a top-level "error" object instead of "choices".
    if "error" in body:
        error_code = body["error"].get("code")
        error_msg  = body["error"].get("message", "unknown error")
        if error_code == 429:
            logger.warning(
                "Model %s returned HTTP 200 with provider-level 429: %s",
                model, error_msg,
            )
            return None, True  # treat as rate-limited → try next in chain
        logger.error(
            "Provider error for model %s (code=%s): %s",
            model, error_code, error_msg,
        )
        return None, False

    # ── Extract content from standard OpenAI-compatible shape ──────────────
    try:
        content: str = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        logger.warning(
            "Non-standard response shape from model %s (body keys: %s) — "
            "skipping to next provider. Detail: %s",
            model, list(body.keys()), exc,
        )
        # Treat as "skip" not "abort" — the next provider may work fine.
        return None, True

    return _parse_vulnerabilities(content), False


# ── Public API ────────────────────────────────────────────────────────────────


async def analyze_code(code: str, language: str) -> list[dict]:
    """
    Analyse *code* written in *language* for security vulnerabilities.

    Iterates through the provider chain in order.  On HTTP 429 (or a missing
    API key) the next provider is tried.  On any other error the chain is
    aborted and ``[]`` is returned immediately to avoid cascading failures.

    Parameters
    ----------
    code:
        Raw source code to analyse.
    language:
        Human-readable language name, e.g. ``"python"`` or ``"javascript"``.

    Returns
    -------
    list[dict]
        A (possibly empty) list of vulnerability dicts.
    """
    models = _get_models()  # read env vars fresh at call time
    model_names = " → ".join(m["name"] for m in models)
    logger.info("Starting analysis. Provider chain: %s", model_names)

    async with httpx.AsyncClient(timeout=60.0) as client:
        for index, entry in enumerate(models):
            model = entry["name"]
            position = "primary" if index == 0 else f"fallback {index}"
            logger.info("Trying %s model: %s", position, model)

            vulns, rate_limited = await _call_model(client, entry, code, language)

            if vulns is not None:
                logger.info("Success with model: %s", model)
                return vulns

            if not rate_limited:
                # Hard failure (network error, bad JSON, non-429 HTTP error) —
                # stop the chain; retrying other providers is unlikely to help.
                logger.error(
                    "Non-recoverable error on model %s — aborting chain.", model
                )
                return []

            # Rate-limited or key missing → try the next provider
            next_model = models[index + 1]["name"] if index < len(models) - 1 else None
            if next_model:
                logger.warning(
                    "Model %s unavailable (rate-limited/key missing) — "
                    "trying next: %s",
                    model,
                    next_model,
                )

    # Every provider in the chain was rate-limited or had a missing key
    logger.error(
        "All providers exhausted (%s). Returning empty vulnerabilities.",
        model_names,
    )
    return []
