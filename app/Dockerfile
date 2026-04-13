# ============================================================
# Matt // Classified — Dockerfile
# Multi-stage build: compile deps in builder, copy only
# runtime artefacts into the final minimal image.
# ============================================================

# ---- Stage 1: build ----------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install only what's needed to compile Python packages.
# We copy requirements first for better layer caching.
COPY requirements.txt .

RUN pip install --upgrade pip --no-cache-dir \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Stage 2: runtime --------------------------------------
FROM python:3.12-slim AS runtime

# Create an unprivileged user.
# uid/gid 10001 are in the non-system range; no home dir needed.
RUN groupadd --gid 10001 appgroup \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy only application source — no tests, no .env, no dev files
COPY main.py storage.py validation.py rate_limit.py ./
COPY static/ ./static/

# The container filesystem is read-only (enforced by docker-compose).
# The only writable path is /tmp (tmpfs mount from compose).
# Ensure uvicorn writes its own temp files there.
ENV TMPDIR=/tmp

# Drop to unprivileged user for all subsequent operations
USER appuser

# Expose documentation port (actual binding controlled by compose)
EXPOSE 8000

# Uvicorn with proxy-headers enabled so FastAPI sees real X-Forwarded-For
# set by nginx on the host. Trusted proxy validation is done in rate_limit.py.
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--proxy-headers", \
     "--forwarded-allow-ips=*"]
