# Security and deployment notes

## Scope
ARY CyberShield is intended for defensive monitoring of systems you own or are authorized to administer. It does not perform offensive scans, exploit systems, bypass third-party controls, or retaliate against sources of attacks.

## Current controls
- Separate ingestion and administration API keys
- Input validation for event IP addresses
- Basic suspicious-request pattern classification
- Per-process request rate limiting and baseline security response headers
- Audit entries for IP block/unblock requests
- Logging-only firewall adapter contract

## Important limitations
The in-memory limiter is per worker and resets on restart. Put a CDN/reverse proxy/WAF and shared rate limiter in front of the API. Configure trusted proxy handling carefully; never trust arbitrary client-supplied forwarded-for values. The logging-only adapter does not enforce network blocks. Connect a reviewed edge-provider adapter before treating a block as active traffic enforcement.

Do not expose the admin API publicly without TLS, strong randomly generated secrets, network restrictions and additional authentication. Use a production database with migrations and backups. Add alert delivery, retention policies, tenant isolation, role-based access control, operational monitoring and independent security review before production use.

IP geolocation is approximate and does not identify a person or exact residence. Preserve evidence lawfully and limit access to it.


## Telemetry and threat intelligence
Telemetry may contain source IP addresses, request targets, user-agent strings, analyst notes and optional SHA-256 file digests. Do not submit passwords, session cookies, authorization headers, request bodies containing personal data, or uploaded file contents. Restrict dashboard/API access and define a retention policy before production use.

OTX subscribed-pulse synchronization is an operator-triggered import of community indicators. Indicators can be stale or noisy. Import does not trigger automatic IP blocking; analysts must review context before taking response actions.

The per-source traffic anomaly signal is heuristic only. It is not a DDoS mitigation service and must not be used as the sole basis for blocking legitimate clients. Cloudflare actions affect the configured zone and should be reviewed carefully before deployment.
