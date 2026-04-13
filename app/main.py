"""
Matt // Classified — FastAPI application.

Zero-knowledge encrypted notes service.
Server never sees plaintext or encryption keys.

Security model:
- Encryption/decryption is client-only (Web Crypto API).
- The key lives in the URL fragment (#...) — HTTP never sends it to the server.
- Server stores only: id → {ciphertext, iv, has_password} with TTL.
- Logs contain NO note ids, NO payloads, NO raw IPs.
"""

import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from storage import save_note, fetch_and_delete_note, get_redis, note_exists
from validation import CreateNoteRequest, is_valid_note_id
from rate_limit import check_rate_limit, get_client_ip, detect_lua_support, RateLimitRedisError

# ---------------------------------------------------------------------------
# Logging — operational facts only; no payloads, no ids, no raw IPs.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("matt_classified")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY_BYTES = 256 * 1024  # 256 KB


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Matt // Classified v0.1.0 starting up")
    try:
        r = get_redis()
        r.ping()
        logger.info("Redis connection OK")
    except Exception as e:
        logger.warning("Redis not available at startup: %s", type(e).__name__)

    # Detect Lua support ONCE — determines rate-limiter mode for the process lifetime
    try:
        detect_lua_support(get_redis())
    except Exception as e:
        logger.warning("Lua detection error at startup: %s", type(e).__name__)

    yield
    logger.info("Matt // Classified shutting down")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Matt // Classified",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _read_body_streaming(request: Request) -> bytes | None:
    """
    Read request body in chunks, enforcing MAX_BODY_BYTES.

    Checks Content-Length header first (fast-reject before any data is read).
    Then reads the actual stream chunk by chunk, aborting if the real data
    exceeds the limit — prevents OOM from large payloads with no/faked header.

    Returns None if the body exceeds MAX_BODY_BYTES or on stream errors.
    """
    # Fast path: reject by Content-Length header before reading any bytes
    cl_header = request.headers.get("content-length")
    if cl_header is not None:
        try:
            if int(cl_header) > MAX_BODY_BYTES:
                return None
        except ValueError:
            return None  # unparseable Content-Length → reject

    # Read stream chunk by chunk
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                return None
            chunks.append(chunk)
    except Exception:
        return None

    return b"".join(chunks)


def _service_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "SERVICE_UNAVAILABLE"},
        headers={"Retry-After": "10"},
    )


def _rate_limit_response() -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"error": "RATE_LIMITED"},
        headers={"Retry-After": "60"},
    )


def _invalid_payload_response() -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": "INVALID_PAYLOAD"})


def _not_found_response() -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "NOT_FOUND"})


def _apply_rate_limit(request: Request, endpoint: str) -> JSONResponse | None:
    """
    Run rate-limit check. Returns a response if the request must be blocked,
    None if the request may proceed.

    Fail-CLOSED: Redis error → 503. Without Redis the app cannot store or
    retrieve notes anyway, so there is no benefit in allowing the request.
    """
    try:
        r = get_redis()
        ip = get_client_ip(request)
        allowed, _ = check_rate_limit(r, ip, endpoint)
        if not allowed:
            return _rate_limit_response()
        return None
    except RateLimitRedisError:
        logger.error("Rate limit check failed: Redis unavailable — returning 503")
        return _service_unavailable_response()
    except Exception as exc:
        logger.error("Unexpected error in rate limiter: %s: %s", type(exc).__name__, exc)
        return _service_unavailable_response()


# ---------------------------------------------------------------------------
# API: POST /api/notes — create a note
# ---------------------------------------------------------------------------
@app.post("/api/notes", status_code=201)
async def create_note(request: Request):
    # 1. Rate limit (fail-closed)
    blocked = _apply_rate_limit(request, "post_notes")
    if blocked is not None:
        return blocked

    # 2. Content-Type
    if "application/json" not in request.headers.get("content-type", ""):
        return _invalid_payload_response()

    # 3. Body: streaming read with hard size limit
    body = await _read_body_streaming(request)
    if body is None:
        return _invalid_payload_response()

    # 4. Parse + validate (narrow except — no bare Exception)
    try:
        raw = json.loads(body)
        note_req = CreateNoteRequest.model_validate(raw)
    except (ValidationError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return _invalid_payload_response()

    # 5. Generate id and store
    note_id = secrets.token_urlsafe(16)  # → 22 base64url chars

    try:
        save_note(
            note_id,
            {
                "ciphertext": note_req.ciphertext,
                "iv": note_req.iv,
                "has_password": note_req.has_password,
            },
            note_req.ttl_seconds,
        )
    except Exception:
        logger.error("Redis write failure during note creation")
        return _service_unavailable_response()

    logger.info("Note created (ttl=%ds, has_password=%s)", note_req.ttl_seconds, note_req.has_password)
    return JSONResponse(status_code=201, content={"id": note_id})


@app.get("/api/notes/{note_id}/exists")
async def check_note_exists(note_id: str, request: Request):
    """
    Non-destructive existence check — does NOT consume the note.
    Used by the view page to decide initial UI state.
    Returns 204 if exists, 404 if not.
    Rate-limited under the same GET bucket.
    """
    blocked = _apply_rate_limit(request, "get_notes")
    if blocked is not None:
        return blocked

    if not is_valid_note_id(note_id):
        return _not_found_response()

    if note_exists(note_id):
        return JSONResponse(status_code=204, content=None)
    return _not_found_response()

# ---------------------------------------------------------------------------
# API: GET /api/notes/{note_id} — fetch and atomically delete a note
# ---------------------------------------------------------------------------
@app.get("/api/notes/{note_id}")
async def get_note(note_id: str, request: Request):
    # 1. Rate limit (fail-closed)
    blocked = _apply_rate_limit(request, "get_notes")
    if blocked is not None:
        return blocked

    # 2. Validate id format — same 404 for all invalid inputs (no info leakage)
    if not is_valid_note_id(note_id):
        return _not_found_response()

    # 3. Atomic GET+DELETE via GETDEL
    try:
        data = fetch_and_delete_note(note_id)
    except Exception:
        logger.error("Redis read failure during note retrieval")
        return _not_found_response()

    if data is None:
        return _not_found_response()

    logger.info("Note retrieved and deleted (has_password=%s)", data.get("has_password"))
    return JSONResponse(
        status_code=200,
        content={
            "ciphertext": data["ciphertext"],
            "iv": data["iv"],
            "has_password": data["has_password"],
        },
    )


# ---------------------------------------------------------------------------
# Health check — used by Docker healthcheck and load balancers.
# Returns 200 only when Redis is reachable; 503 otherwise.
# Does NOT log every hit to avoid noise.
# ---------------------------------------------------------------------------
@app.get("/healthz", include_in_schema=False)
async def healthz():
    try:
        get_redis().ping()
        return JSONResponse(status_code=200, content={"status": "ok"})
    except Exception:
        return JSONResponse(status_code=503, content={"status": "redis_unavailable"})


# ---------------------------------------------------------------------------
# Frontend routes — serve HTML pages
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/n/{note_id}")
async def view_note_page(note_id: str):
    # Server does NOT check note existence here — prevents messenger
    # preview bots from consuming the note before the recipient opens it.
    return FileResponse(STATIC_DIR / "view.html")


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Entry point (dev only — prod uses Docker + uvicorn CLI)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info")
