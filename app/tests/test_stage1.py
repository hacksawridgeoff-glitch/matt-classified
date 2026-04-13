"""
Stage 1 smoke tests: verify zero-knowledge API flow using fakeredis.
"""

import json
import pytest
import fakeredis

# Patch redis before importing storage / main
import storage
import main as app_module
from fastapi.testclient import TestClient

# --- fixtures ---

@pytest.fixture(autouse=True)
def patch_redis(monkeypatch):
    """Replace real Redis with fakeredis for all tests."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(storage, "_client", fake)
    # Reset between tests
    fake.flushall()
    yield fake


@pytest.fixture
def client():
    return TestClient(app_module.app, raise_server_exceptions=False)


# ---------- helpers ----------

VALID_PAYLOAD = {
    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # valid base64url
    "iv": "AAAAAAAAAA0",         # 12 bytes => 16 base64 chars without padding, but 12 bytes in base64url = 16 chars
    "has_password": False,
    "ttl_seconds": 86400,
}

# AES-GCM IV = 12 bytes. In base64url: ceil(12*4/3) = 16 chars (without padding).
# "AAAAAAAAAAAAAAAA" = 16 chars = 12 bytes
VALID_PAYLOAD["iv"] = "AAAAAAAAAAAAAAAA"  # exactly 16 base64url chars = 12 bytes


def make_note(client, payload=None):
    p = {**VALID_PAYLOAD, **(payload or {})}
    return client.post(
        "/api/notes",
        content=json.dumps(p),
        headers={"Content-Type": "application/json"},
    )


# ---------- tests ----------

def test_create_note_returns_201_and_id(client):
    r = make_note(client)
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    assert len(data["id"]) == 22


def test_get_existing_note_returns_200(client):
    r = make_note(client)
    note_id = r.json()["id"]
    r2 = client.get(f"/api/notes/{note_id}")
    assert r2.status_code == 200
    body = r2.json()
    assert "ciphertext" in body
    assert "iv" in body
    assert "has_password" in body


def test_get_note_deletes_it(client):
    """GET is atomic: second request must return 404."""
    r = make_note(client)
    note_id = r.json()["id"]
    r1 = client.get(f"/api/notes/{note_id}")
    assert r1.status_code == 200
    r2 = client.get(f"/api/notes/{note_id}")
    assert r2.status_code == 404
    assert r2.json() == {"error": "NOT_FOUND"}


def test_get_nonexistent_note_returns_404(client):
    r = client.get("/api/notes/AAAAAAAAAAAAAAAAAAAAAA")  # 22 chars, valid format, not stored
    assert r.status_code == 404
    assert r.json() == {"error": "NOT_FOUND"}


def test_get_invalid_id_returns_404_not_400(client):
    r = client.get("/api/notes/tooshort")
    assert r.status_code == 404
    assert r.json() == {"error": "NOT_FOUND"}


def test_post_invalid_base64_returns_400(client):
    bad = {**VALID_PAYLOAD, "ciphertext": "!!!not-base64url!!!"}
    r = make_note(client, bad)
    assert r.status_code == 400
    assert r.json() == {"error": "INVALID_PAYLOAD"}


def test_post_wrong_iv_length_returns_400(client):
    # 8 bytes = "AAAAAAAAAAA" (11 chars) — not 12 bytes
    bad = {**VALID_PAYLOAD, "iv": "AAAAAAAAAAA"}  # 8 bytes, not 12
    r = make_note(client, bad)
    assert r.status_code == 400
    assert r.json() == {"error": "INVALID_PAYLOAD"}


def test_post_invalid_ttl_returns_400(client):
    bad = {**VALID_PAYLOAD, "ttl_seconds": 12345}  # not in allowed list
    r = make_note(client, bad)
    assert r.status_code == 400
    assert r.json() == {"error": "INVALID_PAYLOAD"}


def test_post_missing_field_returns_400(client):
    bad = {"ciphertext": VALID_PAYLOAD["ciphertext"], "iv": VALID_PAYLOAD["iv"]}
    r = client.post(
        "/api/notes",
        content=json.dumps(bad),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json() == {"error": "INVALID_PAYLOAD"}


def test_post_wrong_content_type_returns_400(client):
    r = client.post("/api/notes", data="plain text", headers={"Content-Type": "text/plain"})
    assert r.status_code == 400
    assert r.json() == {"error": "INVALID_PAYLOAD"}


def test_note_data_preserved(client):
    """Response must return exactly what was stored (minus ttl)."""
    r = make_note(client)
    note_id = r.json()["id"]
    r2 = client.get(f"/api/notes/{note_id}")
    data = r2.json()
    assert data["ciphertext"] == VALID_PAYLOAD["ciphertext"]
    assert data["iv"] == VALID_PAYLOAD["iv"]
    assert data["has_password"] == VALID_PAYLOAD["has_password"]
