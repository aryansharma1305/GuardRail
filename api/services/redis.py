"""
Redis service — rate limiting via the Upstash Redis REST API.

Upstash exposes Redis commands over HTTPS, so no persistent TCP connection
is needed. All requests are plain POST calls authenticated with a Bearer token.

Environment variables
---------------------
UPSTASH_REDIS_REST_URL   : e.g. https://xxxx.upstash.io
UPSTASH_REDIS_REST_TOKEN : your Upstash REST token
"""

from __future__ import annotations

import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import TypedDict

import httpx

logger = logging.getLogger(__name__)

FREE_DAILY_LIMIT = 50


# ── Types ─────────────────────────────────────────────────────────────────────


class RateLimitResult(TypedDict):
    allowed: bool
    remaining: int
    reset_at: str | None


# ── Internal helpers ──────────────────────────────────────────────────────────


def _base_url() -> str:
    url = os.getenv("UPSTASH_REDIS_REST_URL", "").rstrip("/")
    if not url:
        raise EnvironmentError(
            "UPSTASH_REDIS_REST_URL is not set. Add it to your .env file."
        )
    return url


def _token() -> str:
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    if not token:
        raise EnvironmentError(
            "UPSTASH_REDIS_REST_TOKEN is not set. Add it to your .env file."
        )
    return token


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Content-Type": "application/json",
    }


def _rate_key(api_key: str) -> str:
    today = date.today().strftime("%Y-%m-%d")
    return f"ratelimit:{api_key}:{today}"


def _tomorrow_midnight_utc() -> str:
    """ISO-8601 timestamp for the start of the next UTC day."""
    now_utc = datetime.now(tz=timezone.utc)
    tomorrow = (now_utc + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return tomorrow.isoformat()


async def _upstash_post(path: str) -> object:
    """
    POST to the Upstash REST endpoint and return the ``result`` field.

    Upstash always responds with ``{ "result": <value> }``.
    Returns ``None`` on any error so callers can apply safe defaults.
    """
    url = f"{_base_url()}/{path.lstrip('/')}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=_headers())
            resp.raise_for_status()
            return resp.json().get("result")
    except httpx.TimeoutException:
        logger.error("Upstash request timed out: %s", url)
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Upstash HTTP %s for %s: %s",
            exc.response.status_code,
            url,
            exc.response.text,
        )
    except httpx.RequestError as exc:
        logger.error("Network error reaching Upstash (%s): %s", url, exc)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected Upstash error: %s", exc)
    return None


# ── Public API ────────────────────────────────────────────────────────────────


async def check_rate_limit(api_key: str, plan: str = "free") -> RateLimitResult:
    """
    Check whether *api_key* is allowed to make another scan today.

    Parameters
    ----------
    api_key:
        The caller's API key (used as part of the Redis key).
    plan:
        ``"pro"`` bypasses limits entirely; ``"free"`` enforces 50 scans/day.

    Returns
    -------
    RateLimitResult
        ``allowed``   — whether the request may proceed.
        ``remaining`` — scans left in the current window.
        ``reset_at``  — ISO timestamp when the window resets (None for pro).
    """
    if plan == "pro":
        return RateLimitResult(allowed=True, remaining=999_999, reset_at=None)

    key = _rate_key(api_key)
    reset_at = _tomorrow_midnight_utc()

    result = await _upstash_post(f"get/{key}")

    # ``result`` is a string from Redis GET, or None if the key doesn't exist.
    try:
        count = int(result) if result is not None else 0
    except (ValueError, TypeError):
        logger.warning("Unexpected GET result from Upstash: %r — treating as 0", result)
        count = 0

    if count >= FREE_DAILY_LIMIT:
        return RateLimitResult(allowed=False, remaining=0, reset_at=reset_at)

    return RateLimitResult(
        allowed=True,
        remaining=FREE_DAILY_LIMIT - count,
        reset_at=reset_at,
    )


async def increment_usage(api_key: str) -> int:
    """
    Increment the daily scan counter for *api_key*.

    Sets a 24-hour TTL on the first increment so keys expire automatically.

    Returns
    -------
    int
        The new counter value, or ``-1`` if the operation failed.
    """
    key = _rate_key(api_key)

    new_count = await _upstash_post(f"incr/{key}")

    try:
        count = int(new_count)
    except (ValueError, TypeError):
        logger.error("Unexpected INCR result from Upstash: %r", new_count)
        return -1

    # First increment — set TTL so the key expires at midnight (approx).
    if count == 1:
        expire_result = await _upstash_post(f"expire/{key}/86400")
        if expire_result != 1:
            logger.warning(
                "EXPIRE returned unexpected value for key '%s': %r",
                key,
                expire_result,
            )

    return count
