"""
POST /analyze — accepts source code and returns security vulnerabilities
detected by the Claude service via OpenRouter.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from models.schemas import AnalyzeRequest, AnalyzeResponse, Vulnerability
from routes.auth import validate_api_key
from services.claude import analyze_code
from services.redis import check_rate_limit, increment_usage

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Constants ─────────────────────────────────────────────────────────────────

SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "java", "php", "go"}
MAX_CODE_BYTES = 50 * 1024  # 50 KB



# ── Endpoint ──────────────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Scan source code for security vulnerabilities",
    responses={
        400: {"description": "Unsupported language or empty code"},
        401: {"description": "Invalid or missing API key"},
        413: {"description": "Code payload exceeds 50 KB limit"},
        429: {"description": "Daily scan limit reached"},
        500: {"description": "Upstream analysis service error"},
    },
)
async def analyze(request: AnalyzeRequest) -> JSONResponse:
    # 1. Validate API key ──────────────────────────────────────────────────────
    if not request.api_key or not validate_api_key(request.api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

    # 2. Check rate limit ──────────────────────────────────────────────────────
    rate = await check_rate_limit(api_key=request.api_key, plan="free")
    if not rate["allowed"]:
        return JSONResponse(
            status_code=429,
            content={
                "error": (
                    "Daily limit reached. "
                    "Upgrade to Pro for unlimited scans."
                ),
                "reset_at": rate["reset_at"],
            },
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": rate["reset_at"] or "",
            },
        )

    # 3. Validate language ─────────────────────────────────────────────────────
    lang = request.language.strip().lower()
    if lang not in SUPPORTED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported language '{request.language}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}."
            ),
        )

    # 4. Validate code ─────────────────────────────────────────────────────────
    if not request.code or len(request.code.strip()) == 0:
        raise HTTPException(status_code=400, detail="Code cannot be empty")

    if len(request.code.encode("utf-8")) > MAX_CODE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Code payload exceeds the 50 KB limit. Split into smaller chunks.",
        )

    # 5. Run analysis ──────────────────────────────────────────────────────────
    try:
        raw_vulns: list[dict] = await analyze_code(request.code, lang)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error from analyze_code: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="The analysis service encountered an unexpected error.",
        ) from exc

    # 6. Increment usage counter (fire-and-forget style — don't fail the
    #    response if Redis is momentarily unavailable) ─────────────────────────
    try:
        await increment_usage(request.api_key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not increment usage counter: %s", exc)

    # 7. Build response ────────────────────────────────────────────────────────
    vulnerabilities: list[Vulnerability] = []
    for item in raw_vulns:
        try:
            vulnerabilities.append(Vulnerability(**item))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Skipping malformed vulnerability dict: %s — %s", item, exc
            )

    response_body = AnalyzeResponse(
        vulnerabilities=vulnerabilities,
        scan_id=str(uuid.uuid4()),
        language=lang,
        scanned_at=datetime.now(tz=timezone.utc).isoformat(),
    )

    # Remaining is pre-decrement (check was done before INCR), so subtract 1.
    remaining_after = max(0, rate["remaining"] - 1)

    return JSONResponse(
        status_code=200,
        content=response_body.model_dump(),
        headers={
            "X-RateLimit-Remaining": str(remaining_after),
            "X-RateLimit-Reset": rate["reset_at"] or "",
        },
    )
