# ============================================================
# Matt // Classified — Makefile
#
# Requires: docker compose v2 (docker compose, not docker-compose).
# All targets run from the project root (where docker-compose.yml lives).
# ============================================================

.PHONY: up down logs build test

# -- Variables -------------------------------------------------

# Path to the .env file.  Copy .env.example → .env before first use.
ENV_FILE ?= .env

# Container / service names as defined in docker-compose.yml
APP_SERVICE  = app
REDIS_SERVICE = redis

# ============================================================
# Lifecycle targets
# ============================================================

## up — build images (if needed) and start all services in the background
up:
	docker compose --env-file $(ENV_FILE) up --build -d

## down — stop and remove containers (data is ephemeral — nothing to lose)
down:
	docker compose down

## logs — tail logs from all services (Ctrl-C to stop)
logs:
	docker compose logs -f

## build — (re)build the app image without starting services
build:
	docker compose build $(APP_SERVICE)

# ============================================================
# Test targets
# ============================================================

## test — run pytest in the LOCAL virtualenv (fast, no Docker needed)
##        Requires: pip install -r app/requirements-dev.txt
##
## NOTE: pytest and dev dependencies are intentionally excluded from
## the production image (.dockerignore strips tests/ and
## requirements-dev.txt; only requirements.txt is installed).
## This is by design — the prod image stays minimal.
test:
	cd app && python -m pytest -q
