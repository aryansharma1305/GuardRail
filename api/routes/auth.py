"""
auth.py — API key validation and auth utilities.

Phase 2 (current): validates against a hardcoded test key when Supabase
is not configured, so the API works out-of-the-box during development.

Phase 3 (future): full Supabase DB lookup will replace the fallback once
SUPABASE_URL and SUPABASE_SERVICE_KEY are set in the environment.
"""

from __future__ import annotations

import os

from fastapi import APIRouter

router = APIRouter()

# Used when Supabase is not configured (development / CI).
TEST_KEY = "test-key-123"


def validate_api_key(api_key: str) -> bool:
    """
    Return True if *api_key* is valid, False otherwise.

    When SUPABASE_URL is not set the function falls back to a single
    hardcoded test key so the server works without any external database.
    Full Supabase validation will be wired in here during Phase 3.
    """
    # Fallback if Supabase not configured yet
    if not os.getenv("SUPABASE_URL"):
        return api_key == TEST_KEY

    # Supabase validation will go here in Phase 3
    return api_key == TEST_KEY
