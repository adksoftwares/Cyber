# Integrating a protected application

1. Register the application in the CyberShield admin dashboard.
2. Copy its one-time asset key into the protected server's secret manager.
3. Install the helper in `integrations/python/cybershield_client.py` or adapt its small HTTP request for your backend language.
4. Send telemetry from server-side code only. Never put an asset key or admin key in browser JavaScript, mobile client bundles, or a public repository.
5. Derive the client IP only from the actual TCP peer or a reverse proxy whose forwarded-header chain you explicitly trust. Do not accept an arbitrary client-supplied `X-Forwarded-For`.
6. Call the telemetry client asynchronously or through a queue where possible. Its sample helper uses a short timeout and does not raise telemetry network errors into the protected application.
7. For malware-analysis workflows, calculate SHA-256 using a trusted scanner and send the digest as `file_hash`. CyberShield compares the digest to manually configured hash indicators; it does not upload, execute, quarantine, or scan the file.

The sample is a basic integration helper, not a production-ready queue, retry system, or framework middleware. Configure TLS and secrets before use.
