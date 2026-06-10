"""
Guardrail API — application entry point.

Start the dev server with:
    uvicorn api.main:app --reload

The PORT environment variable is injected automatically by Railway (and other
PaaS platforms). It is read here so it can be used if the app is launched
programmatically via ``uvicorn.run()`` in addition to the CLI start command
defined in railway.toml.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env FIRST — before any project module is imported, so that
# module-level os.getenv() calls in services/ and routes/ see the values.
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.schemas import HealthResponse
from routes.analyze import router as analyze_router
from routes.auth import router as auth_router
from routes.usage import router as usage_router

# Railway injects $PORT automatically; fall back to 8000 for local dev.
PORT: int = int(os.getenv("PORT", 8000))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    logger.info("🛡️  Guardrail API starting up…")
    yield
    logger.info("🛡️  Guardrail API shutting down.")


# ── App factory ───────────────────────────────────────────────────────────────


app = FastAPI(
    title="Guardrail",
    description="AI-powered code security scanner.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — allow all origins during development; tighten before production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(analyze_router, prefix="", tags=["Analyze"])
app.include_router(auth_router, prefix="", tags=["Auth"])
app.include_router(usage_router, prefix="", tags=["Usage"])

# ── Core endpoints ────────────────────────────────────────────────────────────


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["Meta"],
)
async def health() -> HealthResponse:
    """Returns ``{ "status": "ok" }`` when the service is running."""
    return HealthResponse(status="ok")
