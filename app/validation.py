"""
Pydantic models + extra validation for Matt // Classified.

Backend never trusts the client — all checks are re-done here.
Every validation failure returns the same 400 INVALID_PAYLOAD to avoid
leaking information about the validator's internal structure.
"""

import base64
import re
from typing import Annotated

from pydantic import BaseModel, field_validator, model_validator, Field
from pydantic import StrictBool, StrictInt

ALLOWED_TTL: frozenset[int] = frozenset([900, 3600, 86400, 604800, 2592000])
BASE64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')
NOTE_ID_RE = re.compile(r'^[A-Za-z0-9_-]{22}$')

# Max decoded ciphertext: 150 KB
MAX_CIPHERTEXT_BYTES = 150 * 1024


def _decode_base64url(value: str) -> bytes:
    """
    Decode a base64url string to bytes.
    Raises ValueError on invalid characters or padding issues.
    """
    if not value or not BASE64URL_RE.match(value):
        raise ValueError("Invalid base64url characters")
    padded = value.replace('-', '+').replace('_', '/')
    remainder = len(padded) % 4
    if remainder:
        padded += '=' * (4 - remainder)
    return base64.b64decode(padded, validate=True)


class CreateNoteRequest(BaseModel):
    """
    Strict request model for POST /api/notes.

    StrictBool and StrictInt prevent Pydantic from silently coercing
    strings like "true" or "86400" to their respective types.
    """

    ciphertext: str
    iv: str
    has_password: StrictBool
    ttl_seconds: StrictInt

    @field_validator('ciphertext')
    @classmethod
    def validate_ciphertext(cls, v: str) -> str:
        if not v:
            raise ValueError("ciphertext is required")
        try:
            decoded = _decode_base64url(v)
        except Exception:
            raise ValueError("Invalid ciphertext encoding")
        if len(decoded) > MAX_CIPHERTEXT_BYTES:
            raise ValueError("Ciphertext exceeds 150 KB limit")
        return v

    @field_validator('iv')
    @classmethod
    def validate_iv(cls, v: str) -> str:
        if not v:
            raise ValueError("iv is required")
        try:
            decoded = _decode_base64url(v)
        except Exception:
            raise ValueError("Invalid IV encoding")
        if len(decoded) != 12:
            raise ValueError(f"IV must be exactly 12 bytes (got {len(decoded)})")
        return v

    @field_validator('ttl_seconds')
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        if v not in ALLOWED_TTL:
            raise ValueError(f"ttl_seconds must be one of {sorted(ALLOWED_TTL)}")
        return v


def is_valid_note_id(note_id: str) -> bool:
    """Check if a note_id is a valid 22-character base64url string."""
    return bool(NOTE_ID_RE.match(note_id))
