"""
Redis storage wrapper for Matt // Classified.
Only stores: id -> {ciphertext, iv, has_password}
Never logs note contents or ids.
"""

import json
import logging
import os

import redis

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _client


def save_note(note_id: str, data: dict, ttl_seconds: int) -> None:
    """Store note in Redis with TTL. Data: {ciphertext, iv, has_password}."""
    r = get_redis()
    payload = json.dumps(
        {
            "ciphertext": data["ciphertext"],
            "iv": data["iv"],
            "has_password": data["has_password"],
        }
    )
    r.set(f"note:{note_id}", payload, ex=ttl_seconds)


def fetch_and_delete_note(note_id: str) -> dict | None:
    """
    Atomically GET and DELETE a note via GETDEL.
    Returns parsed dict or None if not found / expired.
    """
    r = get_redis()
    raw = r.getdel(f"note:{note_id}")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.error("Failed to parse stored note (corrupted data)")
        return None
def note_exists(note_id: str) -> bool:
    """
    Check if a note exists without consuming it.
    Used by the view page to show the correct initial state
    (reveal prompt vs. not-found screen) on page load.
    """
    r = get_redis()
    try:
        return bool(r.exists(f"note:{note_id}"))
    except Exception:
        logger.error("Redis read failure during existence check")
        return False
