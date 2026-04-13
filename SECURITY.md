# Security Model

## Zero-knowledge guarantee

The server never sees plaintext content or encryption keys.

- All encryption and decryption happens in the browser via Web Crypto API (AES-256-GCM).
- Each note is encrypted with a random 256-bit key generated client-side.
- The key lives in the URL fragment (`#…`) which is never transmitted to the server.
- Optional password adds a PBKDF2-wrapped layer (600000 iterations, SHA-256).

## What the server stores

Only: `{id, ciphertext, iv, has_password}` in Redis, in-memory only, with TTL.
No disk persistence (AOF/RDB disabled, /data is tmpfs).

## How to verify

Open DevTools → Network tab → create a note.
Inspect the POST /api/notes request body: only ciphertext and iv are sent.
Inspect the generated URL: everything after `#` is the key, which HTTP never forwards.

## Reporting vulnerabilities

Found a security issue? Please open a GitHub issue or contact the maintainer.
