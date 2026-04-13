# Matt // Classified

Zero-knowledge one-time encrypted notes service.

The server **never** sees plaintext. Encryption and decryption happen entirely in the browser using AES-256-GCM (Web Crypto API). The encryption key lives only in the URL fragment (`#…`) — fragments are never sent to the server by the browser's HTTP stack.

---

## Архитектура безопасности

| Что храним на сервере | Что не храним |
|---|---|
| Ciphertext (зашифрованные данные) | Открытый текст |
| IV (вектор инициализации) | Ключ шифрования |
| `has_password` — булев флаг | Сам пароль или его хэш |
| TTL (автоудаление через Redis) | IP-адреса, user-agent, идентификаторы запросов |

Заметка **удаляется атомарно** при первом открытии (`GETDEL`) — прочитать дважды невозможно.

---

## Быстрый старт (разработка)

```bash
# 1. Создать виртуальное окружение
python -m venv .venv && source .venv/bin/activate

# 2. Установить зависимости (dev-набор включает fakeredis и pytest)
pip install -r app/requirements-dev.txt

# 3. Запустить тесты
make test          # или: cd app && python -m pytest -q

# 4. Запустить сервер локально (нужен запущенный Redis)
cd app && python main.py
```

---

## Развёртывание

### Требования

- Linux-хост с Docker Engine ≥ 24 и docker compose v2
- nginx (на хосте) с сертификатом Let's Encrypt (см. `deploy/`)
- Открытые порты: 80, 443 (для nginx); порт 8000 **только на loopback**

### 1. Подготовка окружения

```bash
# Клонировать репозиторий
git clone https://github.com/youruser/matt-classified.git
cd matt-classified

# Скопировать шаблон

cp .env.example .env

# Сгенерировать сильный пароль для Redis и вписать его в .env
# (обязательно — без этого запуск не сработает)
REDIS_PASS=$(openssl rand -base64 32)
sed -i "s|REDIS_PASSWORD=change-me-to-a-long-random-string|REDIS_PASSWORD=${REDIS_PASS}|" .env

# Проверить остальные переменные (LOG_LEVEL, TRUSTED_PROXIES)
nano .env
```

Обязательные переменные в `.env`:

```dotenv
# Пароль Redis — ОБЯЗАТЕЛЬНО смените перед первым запуском (см. шаг ниже)
REDIS_PASSWORD=change-me-to-a-long-random-string

# Redis URL — использует пароль выше
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

# Уровень логирования (INFO в prod, DEBUG только при отладке)
LOG_LEVEL=INFO

# Rate limiting: максимум запросов за 60-секундное окно, на один IP
# Окно фиксировано в коде (60 секунд)
RATE_LIMIT_POST=10      # лимит для POST /api/notes
RATE_LIMIT_GET=60       # лимит для GET /api/notes/{id}
RATE_LIMIT_GLOBAL=120   # общий лимит по всем эндпоинтам

# CIDR-список доверенных прокси (XFF доверяется только от них).
# На проде: обычно достаточно 127.0.0.1 (локальный nginx).
TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8
```

### 2. Сборка и запуск

```bash
# Собрать образы и поднять все сервисы в фоне
make up

# Посмотреть логи в реальном времени
make logs

# Остановить
make down
```

Сервис будет доступен по адресу `http://127.0.0.1:8000` — только с localhost. Прямой доступ из интернета закрыт.

### 3. nginx на хосте

Конфигурация nginx и инструкция по получению сертификата Let's Encrypt находятся в `deploy/` (Этап 5). Основной принцип:

```nginx
server {
    listen 443 ssl;
    server_name mattclassified.ru;

    # ... ssl_certificate, ssl_certificate_key ...

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Защита от slowloris и крупных тел на уровне nginx
        client_max_body_size 300k;
        proxy_read_timeout   30s;
    }
}
```

### 4. Health check

```bash
curl http://127.0.0.1:8000/healthz
# {"status":"ok"}  — Redis доступен
# {"status":"redis_unavailable"} + HTTP 503 — проблема с Redis
```

Docker также периодически опрашивает `/healthz` — контейнер помечается `unhealthy` если Redis недоступен.

### 5. Тесты

```bash
# Запустить pytest локально (требует virtualenv с dev-зависимостями)
make test
```

> Dev-зависимости и `tests/` намеренно исключены из продакшен-образа — pytest внутри контейнера недоступен.

---

## Makefile — справочник целей

| Цель | Что делает |
|---|---|
| `make up` | Собрать образы и запустить в фоне (`--build -d`) |
| `make down` | Остановить и удалить контейнеры |
| `make logs` | Следить за логами всех сервисов (`-f`) |
| `make build` | Пересобрать только образ `app` |
| `make test` | pytest в локальном virtualenv (`pip install -r app/requirements-dev.txt`) |

---

## Структура проекта

```
matt-classified/
├── .env.example          # Шаблон переменных окружения
├── docker-compose.yml    # Оркестрация: app + redis
├── Makefile              # Удобные команды
├── README.md             # Этот файл
├── app/
│   ├── Dockerfile        # Multi-stage build (python:3.12-slim)
│   ├── .dockerignore
│   ├── main.py           # FastAPI-приложение
│   ├── storage.py        # Redis CRUD
│   ├── validation.py     # Pydantic-модели
│   ├── rate_limit.py     # Sliding window (Lua / fallback)
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── pytest.ini
│   ├── static/
│   │   ├── index.html    # Страница создания заметки
│   │   ├── view.html     # Страница просмотра заметки
│   │   └── js/
│   │       ├── crypto.js # Крипто-логика (не изменять)
│   │       ├── create.js
│   │       └── view.js
│   └── tests/
│       ├── conftest.py
│       ├── test_api.py
│       └── test_stage1.py
└── deploy/               # nginx + Let's Encrypt (Этап 5)
```

---

## Безопасность в деталях

- **Read-only filesystem** — оба контейнера запускаются с `read_only: true`; единственный writable path — `/tmp` (tmpfs, 16 МБ, `noexec`)
- **Dropped capabilities** — `cap_drop: [ALL]`; никаких системных привилегий
- **No-new-privileges** — `security_opt: [no-new-privileges:true]`
- **Непривилегированные пользователи** — app: uid 10001, redis: uid 999
- **Redis не exposed** — порт 6379 не пробрасывается на хост; Redis доступен только из internal Docker-сети
- **App на loopback** — `127.0.0.1:8000:8000`; снаружи только через nginx
- **Fail-closed rate limiter** — ошибка Redis → 503, а не пропуск запроса
- **Lua sliding window** — атомарный rate limit без race condition
- **Trusted proxies** — XFF доверяется только от CIDR из `TRUSTED_PROXIES`
