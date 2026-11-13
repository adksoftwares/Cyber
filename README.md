# ARY CyberShield

A defensive security monitoring foundation with a FastAPI backend and React SOC dashboard.

## Included
- Authenticated telemetry ingestion at `POST /api/events` using `X-Ingest-Key`
- Pattern classification for SQL injection indicators, XSS probes, path traversal and common scanner paths
- Admin-protected summary and event APIs using `X-Admin-Key`
- Admin IP block/unblock records and audit entries
- Baseline API rate limiting and security response headers
- Database dependency health reporting and high-severity server log alerts
- Explicit dashboard CORS allowlist
- Security hardening notes and starter unit tests
- React dashboard for event monitoring and manual IP block actions
- Dockerfiles and Docker Compose scaffolding

## Start the API
1. Copy `.env.example` to `.env` and replace both keys with long random values.
2. Run `docker compose up --build`.
3. API health: `http://localhost:8000/health`
4. API docs: `http://localhost:8000/docs`

The dashboard source is in `frontend/`. Run `npm install` and `npm run dev` from that directory. Set `VITE_API_URL` if the API is not at `http://localhost:8000`.

## API examples
Send an event:
```bash
curl -X POST http://localhost:8000/api/events \
  -H 'Content-Type: application/json' \
  -H 'X-Ingest-Key: YOUR_INGEST_KEY' \
  -d '{"source_ip":"203.0.113.10","target":"/search?q=test","method":"GET","detail":"example request"}'
```

Read the summary:
```bash
curl http://localhost:8000/api/summary -H 'X-Admin-Key: YOUR_ADMIN_KEY'
```

## Important production limitations
This repository is a starter control plane, not a certified production firewall or complete WAF/IDS/IPS. The IP block endpoint stores denylist state; enforcement must be connected to an actual reverse proxy, firewall, CDN or edge security provider. The current pattern classifier is intentionally simple and will produce false positives/negatives. The built-in rate limiter is in-memory and per process; it is not a replacement for a shared edge rate limiter. High-severity alerts currently go to server logs only. IP block actions are recorded and logged by a placeholder adapter; they do not block network traffic. Configure the dashboard origin in the backend CORS allowlist before deployment. Before production use, add TLS, secret management, persistent production database, migrations, rate limiting, strict network controls, structured logging, alert delivery, threat-intelligence feeds, robust validation, tests, monitoring and independent security review.

IP geolocation is approximate and cannot reliably identify a person or exact home address. Use evidence collection only for systems you own or are authorized to protect. No hack-back or unauthorized intrusion functionality is included.
