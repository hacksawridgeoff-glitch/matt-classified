"""
Shared pytest fixtures for Matt // Classified.
"""

import pytest
import fakeredis
from fastapi.testclient import TestClient

import storage
import rate_limit as rl_module
import main as app_module


@pytest.fixture(autouse=True)
def patch_redis(monkeypatch):
    """
    Replace all Redis clients with a single in-memory fakeredis instance.

    - Patches storage.get_redis() so both the storage layer and the rate-limit
      layer share the same fake client.
    - Calls detect_lua_support() on the fake so that _LUA_SUPPORTED is set to
      False (fakeredis doesn't implement eval), enabling the non-atomic fallback
      path that is safe for tests.
    - Resets _LUA_SUPPORTED after each test to avoid cross-test contamination.
    """
    fake = fakeredis.FakeRedis(decode_responses=True)

    monkeypatch.setattr(storage, "_client", fake)
    monkeypatch.setattr(storage, "get_redis", lambda: fake)

    # Initialise Lua detection for this test (sets _LUA_SUPPORTED = False)
    rl_module.detect_lua_support(fake)

    fake.flushall()
    yield fake
    fake.flushall()

    # Reset so a later test that patches differently starts clean
    monkeypatch.setattr(rl_module, "_LUA_SUPPORTED", None)


@pytest.fixture
def client(patch_redis):
    return TestClient(app_module.app, raise_server_exceptions=False)


# ---------- Canonical valid payload ----------
# AES-GCM IV = 12 bytes → 16 base64url chars (no padding).
VALID_IV = "AAAAAAAAAAAAAAAA"   # 16 chars = 12 bytes
VALID_CT = "A" * 60             # valid base64url, well under 150 KB

VALID_PAYLOAD = {
    "ciphertext": VALID_CT,
    "iv": VALID_IV,
    "has_password": False,
    "ttl_seconds": 86400,
}


def post_note(client, overrides=None, xff: str | None = None):
    """Helper: POST /api/notes with optional payload overrides and XFF header."""
    import json
    payload = {**VALID_PAYLOAD, **(overrides or {})}
    headers = {"Content-Type": "application/json"}
    if xff:
        headers["X-Forwarded-For"] = xff
    return client.post(
        "/api/notes",
        content=json.dumps(payload),
        headers=headers,
    )
