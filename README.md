# ARY CyberShield

A defensive security monitoring control plane with a FastAPI backend and React SOC dashboard.

## Current capabilities
- Authenticated global telemetry ingestion and per-asset ingestion keys
- Protected asset registry for websites, APIs, applications, databases and admin panels
- Event-to-asset association and per-asset event filtering
- Pattern classification for common SQL injection, XSS, path traversal and scanner probes
- Manual threat-indicator registry for IP addresses, domains and SHA-256 hashes
- Automatic source-IP IOC correlation during event ingestion; matching IP indicators raise high-severity events
- Admin-protected event, summary, asset, indicator, block and audit APIs
- Baseline per-process rate limiting, security response headers, health reporting and server-log alerts
- React SOC dashboard, Docker scaffolding and starter tests

## Start
1. Copy .env.example to .env and replace both keys with long random values.
2. Run docker compose up --build.
3. API health: http://localhost:8000/health; interactive API docs: http://localhost:8000/docs.
4. Dashboard source is in frontend/; run npm install and npm run dev.

## Multi-asset ingestion
Create an asset with POST /api/assets using X-Admin-Key and a JSON body such as:
{"name":"Public website","base_url":"https://example.com","asset_type":"website","description":"Production website"}
The response contains a randomly generated asset_key. Store it securely; it is displayed only once. Send telemetry to the returned ingest_endpoint with the X-Asset-Key header. Asset keys are stored as SHA-256 hashes, not plaintext. Deactivate an asset with DELETE /api/assets/{asset_id}.

## Threat indicators
Add indicators through POST /api/indicators with an admin key. Supported types: ip, domain, and sha256. Current automatic correlation is for source IP indicators only. Domain/hash indicators are stored for analyst workflows and future enrichment; they are not yet automatically extracted from request traffic. No external feed is downloaded automatically.

## Important limitations
This is a starter defensive control plane, not a certified production firewall, complete WAF/IDS/IPS or full SOC. IP block records are stored and logged only; they do not block network traffic until a real reverse-proxy, firewall, CDN or edge-provider adapter is configured. Threat intelligence is manually managed; there is no live feed sync, reputation scoring service or automatic domain/hash extraction. The classifier is simple and can produce false positives/negatives. Rate limiting is in-memory and per process. Alerts currently go to server logs only. The dashboard frontend still needs corresponding asset and IOC management screens. Configure CORS origins, TLS, secret management, database migrations/backups, shared edge rate limits, alert delivery, monitoring and independent security review before production deployment.

IP geolocation is approximate and cannot reliably identify a person or exact home address. Use evidence collection only on systems you own or are authorized to protect. No hack-back or unauthorized intrusion capability is included.
