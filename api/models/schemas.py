"""
Pydantic models / schemas for the Guardrail API.
"""

from __future__ import annotations

from pydantic import BaseModel


# ── Analyze ───────────────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    code: str
    language: str
    api_key: str


class Vulnerability(BaseModel):
    id: str
    title: str
    severity: str  # critical | high | medium | low
    line: int
    description: str
    fix: str
    fixed_code: str


class AnalyzeResponse(BaseModel):
    vulnerabilities: list[Vulnerability]
    scan_id: str
    language: str
    scanned_at: str


# ── Health ────────────────────────────────────────────────────────────────────


class HealthResponse(BaseModel):
    status: str = "ok"


# ── Generic error ─────────────────────────────────────────────────────────────


class ErrorDetail(BaseModel):
    code: str
    message: str
