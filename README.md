# ARY CyberShield

A defensive security monitoring control plane with a FastAPI backend and React SOC dashboard.

## Current capabilities
- Authenticated global telemetry ingestion and per-asset ingestion keys
- Protected asset registry for websites, APIs, applications, databases and admin panels
- Event-to-asset association and per-asset event filtering
- Pattern classification for common SQL injection, XSS, path traversal and scanner probes
- SHA-256 file-digest evidence correlation when a trusted scanner supplies the digest
- Traffic-volume analytics and a basic per-source rate-anomaly heuristic
- Active denylist review/unblock, administrative audit history and automatic dashboard refresh
- Manual threat-indicator registry for IP addresses, domains and SHA-256 hashes
- Source-IP, request-host and optional telemetry SHA-256 correlation against active indicators
- Optional Cloudflare zone IP Access Rules adapter for actual edge IP block/unblock actions when configured
- Automatic IP, domain and supplied SHA-256 IOC correlation during event ingestion
- Admin-protected event, summary, asset, indicator, block, audit and traffic analytics APIs
- Baseline per-process rate limiting, security response headers, health reporting and server-log alerts
- React SOC dashboard, Docker scaffolding, Python server-side telemetry helper and starter tests

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
Add indicators through POST /api/indicators with an admin key. Supported types: ip, domain, and sha256. Automatic correlation checks source IPs, request hostnames and an optional server-computed SHA-256 file digest. Hash matching only works when the trusted protected application submits the digest; CyberShield does not scan files. No external feed is downloaded automatically.

## Optional Cloudflare edge enforcement
Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in the backend environment to enable the Cloudflare adapter. Use a narrowly scoped token for the specific zone with the permissions required to manage IP Access Rules. The dashboard block action then attempts to create a Cloudflare IP block and records the returned provider rule ID; unblocking removes that exact provider rule. If credentials are absent or the provider call fails, the denylist record is still saved but the API reports enforcement as not applied. This integration has not been run or verified in this repository session. Review Cloudflare API permissions, plan availability and current API documentation before enabling it in production.

## Traffic analytics

`GET /api/analytics/traffic?minutes=5` groups recent telemetry by source IP. A simple 60-events-per-source-per-minute heuristic marks a high-severity `traffic_rate_anomaly`; this is not volumetric DDoS protection and may produce false positives or be evaded.

## Important limitations
This is a development control plane, not a certified production firewall, complete WAF/IDS/IPS or full SOC. Local denylist records do not block traffic unless the Cloudflare adapter is correctly configured and the provider confirms the rule. Threat intelligence is manually managed; no live feed sync or reputation scoring service is included. The classifier is heuristic and may produce false positives/negatives. Rate limiting is in-memory and per process. Alerts currently go to server logs only. The dashboard includes asset and IOC management, active denylist controls, recent audit history and traffic-volume analytics. Configure CORS origins, TLS, secret management, formal database migrations/backups, shared edge rate limits, alert delivery, monitoring and independent security review before production deployment.

IP geolocation is approximate and cannot reliably identify a person or exact home address. Use evidence collection only on systems you own or are authorized to protect. No hack-back or unauthorized intrusion capability is included.
