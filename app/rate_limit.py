"""
Application-level rate limiting for Matt // Classified.

Design decisions:
- Sliding-window counters stored in Redis sorted sets.
- Atomic execution via Lua script (detected once at startup).
- Fail-CLOSED: any Redis error → deny the request (503). Without Redis the
  app cannot store notes anyway, so there is no reason to allow traffic.
- Client IP is SHA-256 hashed with a daily-rotating in-process salt —
  raw IPs never appear in Redis keys or log lines.
- X-Forwarded-For is only trusted when the direct TCP peer is in the
  TRUSTED_PROXIES list (env var, comma-separated CIDRs/IPs).

Limits (must match nginx config):
  POST /api/notes  — 10 req / 60 s per IP
  GET  /api/notes  — 60 req / 60 s per IP
  ALL  /api/*      — 120 req / 60 s per IP  (global guard)
"""

import hashlib
import ipaddress
import logging
import os
import time

logger = logging.getLogger("matt_classified.rate_limit")

WINDOW_SECONDS = 60
LIMIT_POST_NOTES = int(os.getenv("RATE_LIMIT_POST", "10"))
LIMIT_GET_NOTES  = int(os.getenv("RATE_LIMIT_GET", "60"))
LIMIT_GLOBAL     = int(os.getenv("RATE_LIMIT_GLOBAL", "120"))

# ---------------------------------------------------------------------------
# Trusted proxy detection for X-Forwarded-For
# ---------------------------------------------------------------------------
_RAW_TRUSTED = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8")

def _parse_trusted_proxies(raw: str) -> list:
    """Parse TRUSTED_PROXIES env var into a list of IPv4Network / IPv6Network objects."""
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Invalid TRUSTED_PROXIES entry (ignored): %r", item)
    return networks

_TRUSTED_NETWORKS: list = _parse_trusted_proxies(_RAW_TRUSTED)


def _is_trusted_proxy(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _TRUSTED_NETWORKS)
    except ValueError:
        # Non-IP strings (e.g. "testclient" from Starlette TestClient, unix sockets)
        # are never trusted as proxies in production.
        return False


def get_client_ip(request) -> str:
    """
    Return the real client IP.

    X-Forwarded-For is only trusted when the direct TCP peer
    (request.client.host) is in TRUSTED_PROXIES. Otherwise the
    header is ignored and the direct connection IP is used.
    """
    peer_host = request.client.host if request.client else "unknown"

    if _is_trusted_proxy(peer_host):
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()

    return peer_host


# ---------------------------------------------------------------------------
# IP hashing
# ---------------------------------------------------------------------------
def _daily_salt() -> str:
    day = time.strftime("%Y-%m-%d")
    return hashlib.sha256(f"matt-classified-salt-{day}".encode()).hexdigest()[:16]


def _hash_ip(ip: str) -> str:
    """One-way hash of IP, rotated daily — safe as Redis key."""
    return hashlib.sha256(f"{_daily_salt()}:{ip}".encode()).hexdigest()[:20]


# ---------------------------------------------------------------------------
# Lua script (atomic sliding-window)
# ---------------------------------------------------------------------------
_LUA_SCRIPT = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local window = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)

if count < limit then
    local member = tostring(now) .. '-' .. tostring(math.random(0, 999999))
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window + 1)
    return {1, limit - count - 1}
else
    return {0, 0}
end
"""

# ---------------------------------------------------------------------------
# One-time Lua capability detection
# ---------------------------------------------------------------------------
# Populated by detect_lua_support() called from app lifespan.
# None  = not yet detected (call detect_lua_support() first)
# True  = use Lua (real Redis ≥ 2.6)
# False = use non-atomic fallback (fakeredis / Lua not available)
_LUA_SUPPORTED: bool | None = None


def detect_lua_support(redis_client) -> bool:
    """
    Probe whether the Redis client supports Lua eval.
    Called ONCE at application startup; result stored in module-level flag.

    Raises nothing — logs and returns False if detection fails.
    """
    global _LUA_SUPPORTED
    try:
        result = redis_client.eval("return 1", 0)
        _LUA_SUPPORTED = (result == 1)
    except (AttributeError, NotImplementedError):
        # fakeredis or other client without eval support
        logger.info("Redis client does not support Lua eval — using non-atomic fallback")
        _LUA_SUPPORTED = False
    except Exception as exc:
        # Real Redis error during startup probe — treat as no-Lua for now,
        # but log at WARNING because this is unexpected.
        logger.warning("Lua detection failed (%s: %s) — using fallback", type(exc).__name__, exc)
        _LUA_SUPPORTED = False
    logger.info("Rate limiter Lua mode: %s", _LUA_SUPPORTED)
    return _LUA_SUPPORTED


# ---------------------------------------------------------------------------
# Sliding-window core
# ---------------------------------------------------------------------------
def _sliding_window_lua(redis_client, key: str, limit: int, window: int) -> tuple[bool, int]:
    """
    Atomic sliding-window check via Lua.
    Any exception → caller must treat as fail-closed.
    """
    now_ms   = int(time.time() * 1000)
    cutoff_ms = now_ms - window * 1000
    result = redis_client.eval(_LUA_SCRIPT, 1, key, now_ms, cutoff_ms, limit, window)
    return bool(result[0]), int(result[1])


def _sliding_window_fallback(redis_client, key: str, limit: int, window: int) -> tuple[bool, int]:
    """
    Non-atomic fallback for clients without Lua (fakeredis in tests).
    Safe enough for test isolation; MUST NOT be used in production.
    """
    now_ms    = int(time.time() * 1000)
    cutoff_ms = now_ms - window * 1000

    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(key, "-inf", cutoff_ms)
    pipe.zcard(key)
    _, count = pipe.execute()

    if count < limit:
        member = f"{now_ms}-{os.urandom(4).hex()}"
        redis_client.zadd(key, {member: now_ms})
        redis_client.expire(key, window + 1)
        return True, limit - count - 1
    return False, 0


def _check_one(redis_client, key: str, limit: int, window: int) -> bool:
    """
    Run one sliding-window check.

    Returns True (allowed) or False (blocked).
    Raises RateLimitError on Redis failure in Lua mode (→ caller returns 503).
    """
    if _LUA_SUPPORTED is None:
        raise RuntimeError("detect_lua_support() was not called at startup")

    if _LUA_SUPPORTED:
        # Lua mode: any exception is a real Redis failure → fail-closed
        try:
            allowed, _ = _sliding_window_lua(redis_client, key, limit, window)
            return allowed
        except Exception as exc:
            logger.error("Redis error in rate limiter (Lua): %s: %s", type(exc).__name__, exc)
            raise RateLimitRedisError() from exc
    else:
        # Fallback mode (test environment only)
        allowed, _ = _sliding_window_fallback(redis_client, key, limit, window)
        return allowed


class RateLimitRedisError(Exception):
    """Raised when Redis is unavailable during a rate-limit check (fail-closed path)."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def check_rate_limit(redis_client, ip: str, endpoint: str) -> tuple[bool, str]:
    """
    Check all applicable rate limits for a request.

    Returns:
        (allowed: bool, limit_type: str)
        limit_type is non-empty when a limit was hit.

    Raises:
        RateLimitRedisError — Redis unavailable in Lua mode (caller → 503).
    """
    ip_hash = _hash_ip(ip)

    # 1. Global limit
    if not _check_one(redis_client, f"rl:global:{ip_hash}", LIMIT_GLOBAL, WINDOW_SECONDS):
        logger.warning("Rate limit hit: global (ip_hash=%.8s)", ip_hash)
        return False, "global"

    # 2. Endpoint-specific limit
    if endpoint == "post_notes":
        if not _check_one(redis_client, f"rl:post:{ip_hash}", LIMIT_POST_NOTES, WINDOW_SECONDS):
            logger.warning("Rate limit hit: post_notes (ip_hash=%.8s)", ip_hash)
            return False, "post_notes"

    elif endpoint == "get_notes":
        if not _check_one(redis_client, f"rl:get:{ip_hash}", LIMIT_GET_NOTES, WINDOW_SECONDS):
            logger.warning("Rate limit hit: get_notes (ip_hash=%.8s)", ip_hash)
            return False, "get_notes"

    return True, ""
