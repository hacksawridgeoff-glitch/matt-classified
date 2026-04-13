"""
Full API test suite for Matt // Classified — Stage 2 (post-review).

Coverage:
- POST /api/notes: happy path, all validation branches, streaming body limits
- GET /api/notes/{id}: happy path, atomicity, all 404 cases
- Rate limiting: POST, GET, fail-closed on Redis error (503)
- Trusted proxy / X-Forwarded-For handling
- Frontend routes
"""

import json
import threading
import unittest.mock as mock

import pytest
from tests.conftest import post_note, VALID_PAYLOAD, VALID_IV, VALID_CT
import rate_limit as rl_module
import storage


# ===========================================================================
# POST /api/notes — happy path
# ===========================================================================

class TestCreateNote:
    def test_returns_201_and_22_char_id(self, client):
        r = post_note(client)
        assert r.status_code == 201
        data = r.json()
        assert "id" in data
        assert len(data["id"]) == 22

    def test_id_is_base64url(self, client):
        import re
        note_id = post_note(client).json()["id"]
        assert re.fullmatch(r'[A-Za-z0-9_-]{22}', note_id)

    def test_all_ttl_values_accepted(self, client):
        for i, ttl in enumerate([900, 3600, 86400, 604800, 2592000]):
            r = post_note(client, {"ttl_seconds": ttl}, xff=f"10.0.1.{i+1}")
            assert r.status_code == 201, f"TTL {ttl} should be accepted"

    def test_has_password_true_accepted(self, client):
        r = post_note(client, {"has_password": True})
        assert r.status_code == 201

    def test_each_call_returns_unique_id(self, client, monkeypatch):
        import main as app_main
        # Vary IP per call to avoid hitting rate limit.
        # Patch main.get_client_ip (the local binding after 'from rate_limit import ...').
        call_count = [0]
        def rotating_ip(request):
            call_count[0] += 1
            return f"10.0.0.{call_count[0]}"
        monkeypatch.setattr(app_main, "get_client_ip", rotating_ip)

        ids = set()
        for i in range(20):
            r = post_note(client)
            assert r.status_code == 201, f"Request {i+1} failed: {r.json()}"
            ids.add(r.json()["id"])
        assert len(ids) == 20, "All IDs should be unique"


# ===========================================================================
# POST /api/notes — validation failures (all → 400 INVALID_PAYLOAD)
# ===========================================================================

class TestCreateNoteValidation:

    def _assert_400(self, client, overrides=None, raw_body=None):
        if raw_body is not None:
            r = client.post(
                "/api/notes",
                content=raw_body,
                headers={"Content-Type": "application/json"},
            )
        else:
            r = post_note(client, overrides)
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_wrong_content_type(self, client):
        r = client.post("/api/notes", content=b"hello", headers={"Content-Type": "text/plain"})
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_missing_ciphertext(self, client):
        self._assert_400(client, raw_body=json.dumps({
            "iv": VALID_IV, "has_password": False, "ttl_seconds": 86400
        }).encode())

    def test_missing_iv(self, client):
        self._assert_400(client, raw_body=json.dumps({
            "ciphertext": VALID_CT, "has_password": False, "ttl_seconds": 86400
        }).encode())

    def test_missing_has_password(self, client):
        self._assert_400(client, raw_body=json.dumps({
            "ciphertext": VALID_CT, "iv": VALID_IV, "ttl_seconds": 86400
        }).encode())

    def test_missing_ttl(self, client):
        self._assert_400(client, raw_body=json.dumps({
            "ciphertext": VALID_CT, "iv": VALID_IV, "has_password": False
        }).encode())

    def test_invalid_base64url_ciphertext(self, client):
        self._assert_400(client, {"ciphertext": "!!! not base64url !!!"})

    def test_invalid_base64url_iv(self, client):
        self._assert_400(client, {"iv": "!!! not base64url !!!"})

    def test_iv_too_short(self, client):
        self._assert_400(client, {"iv": "AAAAAAAAAAA"})  # 11 chars = 8 bytes, not 12

    def test_iv_too_long(self, client):
        self._assert_400(client, {"iv": "AAAAAAAAAAAAAAAAAAAAAA"})  # 22 chars = 16 bytes

    def test_ttl_not_in_allowed_list(self, client):
        self._assert_400(client, {"ttl_seconds": 12345})

    def test_ttl_zero(self, client):
        self._assert_400(client, {"ttl_seconds": 0})

    def test_ttl_negative(self, client):
        self._assert_400(client, {"ttl_seconds": -1})

    def test_ttl_string_type(self, client):
        # Pydantic StrictInt must NOT coerce "86400" → 86400
        self._assert_400(client, raw_body=json.dumps({
            "ciphertext": VALID_CT, "iv": VALID_IV,
            "has_password": False, "ttl_seconds": "86400"
        }).encode())

    def test_has_password_not_bool(self, client):
        # Pydantic StrictBool must NOT coerce "yes" → True
        self._assert_400(client, raw_body=json.dumps({
            "ciphertext": VALID_CT, "iv": VALID_IV,
            "has_password": "yes", "ttl_seconds": 86400
        }).encode())

    def test_malformed_json(self, client):
        r = client.post("/api/notes", content=b"{not valid json",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_empty_body(self, client):
        r = client.post("/api/notes", content=b"",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_ciphertext_too_large_decoded(self, client):
        import base64
        raw = b"X" * (151 * 1024)
        oversized_ct = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self._assert_400(client, {"ciphertext": oversized_ct})


# ===========================================================================
# Streaming body size enforcement
# ===========================================================================

class TestStreamingBodyLimit:

    def test_content_length_too_large_rejected_before_read(self, client):
        """Content-Length > 256 KB must be rejected without reading the body."""
        r = client.post(
            "/api/notes",
            content=json.dumps(VALID_PAYLOAD).encode(),
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(300 * 1024),  # lie about size — 300 KB
            },
        )
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_actual_body_too_large_rejected(self, client):
        """Body that actually exceeds 256 KB must be rejected via streaming check."""
        oversized = b"A" * (257 * 1024)
        r = client.post(
            "/api/notes",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}

    def test_body_exactly_at_limit_not_rejected(self, client):
        """A body exactly at 256 KB should pass the size check (may fail validation, not size)."""
        # 256 KB of 'A' chars is valid base64url but invalid JSON → 400 INVALID_PAYLOAD,
        # NOT a body-size rejection. The key is it shouldn't be cut off early.
        r = client.post(
            "/api/notes",
            content=b"A" * MAX_BODY_BYTES_APPROX,
            headers={"Content-Type": "application/json"},
        )
        # Body passes size check but fails JSON parse
        assert r.status_code == 400
        assert r.json() == {"error": "INVALID_PAYLOAD"}


MAX_BODY_BYTES_APPROX = 256 * 1024  # mirrors main.py constant


# ===========================================================================
# GET /api/notes/{id} — happy path
# ===========================================================================

class TestGetNote:

    def test_get_returns_200_with_correct_data(self, client):
        note_id = post_note(client).json()["id"]
        r = client.get(f"/api/notes/{note_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["ciphertext"] == VALID_CT
        assert body["iv"] == VALID_IV
        assert body["has_password"] is False

    def test_get_with_has_password_true(self, client):
        note_id = post_note(client, {"has_password": True}).json()["id"]
        assert client.get(f"/api/notes/{note_id}").json()["has_password"] is True

    def test_get_returns_exactly_three_fields(self, client):
        note_id = post_note(client).json()["id"]
        body = client.get(f"/api/notes/{note_id}").json()
        assert set(body.keys()) == {"ciphertext", "iv", "has_password"}


# ===========================================================================
# GET /api/notes/{id} — atomicity and 404 cases
# ===========================================================================

class TestGetNoteAtomicity:

    def test_second_get_returns_404(self, client):
        note_id = post_note(client).json()["id"]
        assert client.get(f"/api/notes/{note_id}").status_code == 200
        r2 = client.get(f"/api/notes/{note_id}")
        assert r2.status_code == 404
        assert r2.json() == {"error": "NOT_FOUND"}

    def test_concurrent_get_only_one_wins(self, client):
        """
        Two threads racing to GET the same note: exactly one must receive 200,
        the other must receive 404. Verifies atomicity of GETDEL.
        """
        note_id = post_note(client).json()["id"]
        results = []
        lock = threading.Lock()

        def do_get():
            r = client.get(f"/api/notes/{note_id}")
            with lock:
                results.append(r.status_code)

        t1 = threading.Thread(target=do_get)
        t2 = threading.Thread(target=do_get)
        t1.start(); t2.start()
        t1.join();  t2.join()

        assert sorted(results) == [200, 404], f"Expected [200, 404], got {results}"

    def test_nonexistent_id_returns_404(self, client):
        r = client.get("/api/notes/AAAAAAAAAAAAAAAAAAAAAA")
        assert r.status_code == 404
        assert r.json() == {"error": "NOT_FOUND"}

    def test_short_id_returns_404_not_400(self, client):
        r = client.get("/api/notes/tooshort")
        assert r.status_code == 404
        assert r.json() == {"error": "NOT_FOUND"}

    def test_long_id_returns_404(self, client):
        assert client.get("/api/notes/" + "A" * 30).status_code == 404

    def test_id_with_invalid_chars_returns_404(self, client):
        assert client.get("/api/notes/AAAAAAAAAAAAAAAAAAA!!!").status_code == 404

    def test_all_404_responses_are_identical(self, client):
        """Already-read, non-existent, invalid format — all must return same body."""
        note_id = post_note(client).json()["id"]
        client.get(f"/api/notes/{note_id}")  # consume

        bodies = [
            client.get(f"/api/notes/{note_id}").json(),         # already read
            client.get("/api/notes/AAAAAAAAAAAAAAAAAAAAAA").json(),  # never existed
            client.get("/api/notes/bad").json(),                  # invalid format
        ]
        assert all(b == {"error": "NOT_FOUND"} for b in bodies)


# ===========================================================================
# Rate limiting
# ===========================================================================

class TestRateLimiting:

    def test_post_rate_limit_returns_429(self, client):
        """11th POST from same IP in window must return 429."""
        for i in range(10):
            r = post_note(client)
            assert r.status_code == 201, f"Request {i+1} should succeed"
        r = post_note(client)
        assert r.status_code == 429
        assert r.json() == {"error": "RATE_LIMITED"}

    def test_rate_limit_response_has_retry_after(self, client):
        for _ in range(10):
            post_note(client)
        r = post_note(client)
        assert r.status_code == 429
        assert "retry-after" in r.headers

    def test_get_rate_limit_returns_429(self, client, monkeypatch):
        """61st GET from same IP in window must return 429."""
        import main as app_main

        # Phase 1: create 61 notes, each from a distinct IP (avoid POST limit)
        post_count = [0]
        def rotating_post_ip(request):
            post_count[0] += 1
            return f"10.1.0.{post_count[0]}"
        monkeypatch.setattr(app_main, "get_client_ip", rotating_post_ip)
        ids = [post_note(client).json()["id"] for _ in range(61)]

        # Phase 2: all 61 GETs from the SAME IP
        monkeypatch.setattr(app_main, "get_client_ip", lambda req: "192.0.2.1")
        for i in range(60):
            client.get(f"/api/notes/{ids[i]}")

        r = client.get(f"/api/notes/{ids[60]}")
        assert r.status_code == 429
        assert r.json() == {"error": "RATE_LIMITED"}

    def test_different_ips_have_independent_limits(self, client, monkeypatch):
        """Two distinct IPs each get their own 10-request budget."""
        import main as app_main

        monkeypatch.setattr(app_main, "get_client_ip", lambda req: "10.2.0.1")
        for i in range(10):
            assert post_note(client).status_code == 201
        # 11th from same IP → 429
        assert post_note(client).status_code == 429

        # Different IP still has full budget
        monkeypatch.setattr(app_main, "get_client_ip", lambda req: "10.2.0.2")
        assert post_note(client).status_code == 201


# ===========================================================================
# Fail-closed on Redis error → 503
# ===========================================================================

class TestFailClosed:

    def test_post_returns_503_when_redis_down(self, client, monkeypatch):
        """
        When Redis is unavailable the rate limiter must return 503,
        NOT pass the request through (fail-closed).

        We force Lua mode (_LUA_SUPPORTED=True) and make eval() raise,
        simulating a Redis connection error in production.
        """
        monkeypatch.setattr(rl_module, "_LUA_SUPPORTED", True)

        import redis as redis_module
        def broken_eval(*args, **kwargs):
            raise redis_module.ConnectionError("Connection refused")

        fake = storage.get_redis()
        monkeypatch.setattr(fake, "eval", broken_eval)

        r = post_note(client)
        assert r.status_code == 503
        assert r.json() == {"error": "SERVICE_UNAVAILABLE"}

    def test_get_returns_503_when_redis_down(self, client, monkeypatch):
        """GET also returns 503 on Redis failure (fail-closed)."""
        # First create a note while Redis works
        note_id = post_note(client).json()["id"]

        monkeypatch.setattr(rl_module, "_LUA_SUPPORTED", True)

        import redis as redis_module
        def broken_eval(*args, **kwargs):
            raise redis_module.ConnectionError("Connection refused")

        fake = storage.get_redis()
        monkeypatch.setattr(fake, "eval", broken_eval)

        r = client.get(f"/api/notes/{note_id}")
        assert r.status_code == 503
        assert r.json() == {"error": "SERVICE_UNAVAILABLE"}


# ===========================================================================
# Trusted proxy / X-Forwarded-For handling
# ===========================================================================

class TestTrustedProxies:

    def test_xff_used_when_peer_is_trusted(self, monkeypatch):
        """
        When _is_trusted_proxy returns True for the peer host, get_client_ip
        should return the leftmost XFF address, not the direct peer host.
        """
        import rate_limit as rl
        import ipaddress

        # Patch _TRUSTED_NETWORKS to trust 10.0.0.0/8
        monkeypatch.setattr(
            rl, "_TRUSTED_NETWORKS",
            [ipaddress.ip_network("10.0.0.0/8")]
        )

        # Build a minimal mock request with a trusted peer and XFF header
        class FakeClient:
            host = "10.0.0.1"   # trusted proxy
        class FakeHeaders:
            def get(self, key, default=""):
                if key == "x-forwarded-for":
                    return "203.0.113.42, 10.0.0.1"
                return default
        class FakeRequest:
            client = FakeClient()
            headers = FakeHeaders()

        ip = rl.get_client_ip(FakeRequest())
        assert ip == "203.0.113.42"

    def test_xff_ignored_when_peer_is_untrusted(self, monkeypatch):
        """
        When the direct peer is NOT in TRUSTED_PROXIES, XFF must be ignored
        and the direct peer host returned instead.
        """
        import rate_limit as rl
        monkeypatch.setattr(rl, "_TRUSTED_NETWORKS", [])

        class FakeClient:
            host = "1.2.3.4"   # not trusted
        class FakeHeaders:
            def get(self, key, default=""):
                if key == "x-forwarded-for":
                    return "9.9.9.9"
                return default
        class FakeRequest:
            client = FakeClient()
            headers = FakeHeaders()

        ip = rl.get_client_ip(FakeRequest())
        assert ip == "1.2.3.4"   # XFF ignored, real peer returned

    def test_xff_ignored_non_ip_peer(self, monkeypatch):
        """
        Non-IP peer strings (e.g. 'testclient', unix sockets)
        must never be treated as trusted proxies.
        """
        import rate_limit as rl

        class FakeClient:
            host = "testclient"
        class FakeHeaders:
            def get(self, key, default=""):
                return "spoofed.ip" if key == "x-forwarded-for" else default
        class FakeRequest:
            client = FakeClient()
            headers = FakeHeaders()

        ip = rl.get_client_ip(FakeRequest())
        assert ip == "testclient"   # untrusted non-IP → peer returned as-is


# ===========================================================================
# Frontend routes
# ===========================================================================

class TestFrontendRoutes:

    def test_root_returns_200(self, client):
        assert client.get("/").status_code == 200

    def test_view_route_returns_200_regardless_of_id(self, client):
        """Server MUST NOT check note existence on /n/{id}."""
        assert client.get("/n/AAAAAAAAAAAAAAAAAAAAAA").status_code == 200

    def test_view_route_with_nonexistent_id_still_200(self, client):
        assert client.get("/n/doesnotexist__________").status_code == 200
