"""
Dev helper: patch storage module to use fakeredis.
Import this BEFORE importing main to use in-process fake store.
Usage: PYTHONPATH=. python -c "import storage_fake; import uvicorn; uvicorn.run('main:app', ...)"
"""
import fakeredis
import storage

_fake = fakeredis.FakeRedis(decode_responses=True)
storage._client = _fake
print("[DEV] Using fakeredis in-memory store")
