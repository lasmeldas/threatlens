# ThreatLens

A small security monitoring platform (a mini SIEM): upload logs, get ranked alerts, and work through them as an analyst. Built by [Beamlak](https://github.com/lasmeldas).

![CI](https://github.com/lasmeldas/threatlens/actions/workflows/ci.yml/badge.svg)

## Status

| Phase | What | State |
| --- | --- | --- |
| 1 | Django REST API, PostgreSQL, roles, audit log, rule-based detection, tests, CI, Docker | **Done** |
| 2 | React dashboard: sign in, overview with charts, alert list and detail pages, upload and status changes | **Done** |
| 3a | ML model for network attack detection, trained and evaluated on NSL-KDD ([`ml/`](ml/README.md)) | **Done** |
| 3b | Score uploaded connection records through the API and show them in the dashboard | Planned |
| 4 | Live demo with sample data, screenshots, architecture write-up | Planned |

Phases 1, 2 and 3a are built. 3b and 4 are what I am building next.

## What phase 1 does

- You send an OpenSSH auth log to the API (as text or a file).
- The detection engine (the rules from my tool [authwatch](https://github.com/lasmeldas/authwatch)) flags source IPs:
  - **critical**: a login succeeded right after a burst of failures
  - **high**: a brute-force burst (5 failures in 300 seconds by default)
  - **medium**: slow username spraying that stays under the burst threshold
- Alerts are stored, filterable, and have a status an analyst can change: `new`, `investigating`, `resolved`, `false_positive`.
- Every upload and every status change is written to an audit log.

## The dashboard

- **Sign in** with a username and password. The token is kept for this browser tab only and is revoked when you sign out.
- **Overview:** totals, alerts by severity, status and type, the most-flagged addresses, and (for analysts) a form to analyse a log.
- **Alerts:** filter by severity, status, type and address, sort, and page through results. The filters live in the URL, so a filtered view can be shared.
- **Alert detail:** what happened, which usernames were tried, when, and (for analysts) buttons to set the status.
- **Roles are respected in the UI** (viewers get no upload form or status buttons), but the real check is on the server.

## Run it

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DJANGO_DEBUG=1                  # local development only
python manage.py migrate
THREATLENS_PASSWORD='a-long-passphrase-here' python manage.py create_user ana --role analyst
python manage.py runserver
```

The dashboard in development mode (needs the API running on port 8000):

```bash
cd frontend && npm install && npm run dev      # http://localhost:5173
```

With Docker (dashboard, API and PostgreSQL):

```bash
cp .env.example .env        # then set DJANGO_SECRET_KEY and DB_PASSWORD
docker compose up --build   # dashboard at http://localhost:8080
# then create a user:
docker compose exec -e THREATLENS_PASSWORD='a-long-passphrase' api python manage.py create_user ana --role analyst
```

Try it:

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/token/ -H 'Content-Type: application/json' \
  -d '{"username":"ana","password":"a-long-passphrase-here"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -X POST localhost:8000/api/uploads/ -H "Authorization: Token $TOKEN" -F file=@auth.log -F year=2026
curl "localhost:8000/api/alerts/?ordering=severity" -H "Authorization: Token $TOKEN"
```

## API

| Method and path | Who | Purpose |
| --- | --- | --- |
| `POST /api/auth/token/` | anyone (rate limited) | username and password in, token and role out |
| `POST /api/auth/logout/` | signed-in user | revoke the current token |
| `GET /api/me/` | signed-in user | who am I and what is my role |
| `POST /api/uploads/` | analyst | analyse a log (`log` text or `file`, plus `year`, `threshold`, `window`, `spray_users`) |
| `GET /api/uploads/`, `/api/uploads/<id>/` | any signed-in user | past uploads |
| `GET /api/alerts/` | any signed-in user | filter by `severity`, `status`, `kind`, `ip`, `upload`; `ordering=newest\|severity\|failures` |
| `GET /api/alerts/<id>/` | any signed-in user | one alert |
| `PATCH /api/alerts/<id>/` | analyst | change `status` (nothing else can be changed) |
| `GET /api/stats/` | any signed-in user | counts by severity, status and kind, top IPs |
| `GET /api/audit/` | admin | who did what |

Roles: **viewer** can read, **analyst** can also upload and change alert status, **admin** (superuser) can also read the audit log.

## Security decisions

- The app refuses to start in production without `DJANGO_SECRET_KEY`.
- Token login is rate limited, and uploads are rate limited and size limited (2 MB by default).
- Every endpoint needs a token; write access is checked on the server, not just hidden in the UI.
- Alerts are read-only apart from their status, and there is no delete endpoint.
- Passwords must be at least 10 characters and pass Django's common-password checks.
- Production defaults: secure cookies, `nosniff`, no framing.
- The Docker image runs as a non-root user and the API port is bound to localhost only.

Login tokens expire after 12 hours (`TOKEN_TTL_HOURS`), signing in again replaces the old token, and `POST /api/auth/logout/` revokes it.

Known limit: there is no HTTPS in the Compose file, so put it behind a TLS proxy for anything real.

## Tests

```bash
cd backend && DJANGO_DEBUG=1 python manage.py test
```

30 backend tests cover the API, permissions, the audit log, rate limiting, input limits, the user command, and the settings safety checks. One test checks the detection engine against **28 logs whose alerts were produced by the real authwatch**, so the two cannot drift apart unnoticed. CI runs on Python 3.11 to 3.13 with SQLite, and on PostgreSQL 16.

The dashboard has 19 tests (sign-in and session handling, API errors, the charts, filtering, paging, uploading, and role-based buttons):

```bash
cd frontend && npm test
```

## License

MIT
