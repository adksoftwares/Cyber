"""Small server-side telemetry client for ARY CyberShield.

Use only from a trusted backend. Never expose ingest credentials in browser code.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class CyberShieldClient:
    def __init__(self, base_url: str, asset_key: str, asset_id: int, timeout: float = 3.0):
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("Use HTTPS except for loopback development")
        self.endpoint = f"{base_url.rstrip('/')}/api/assets/{int(asset_id)}/events"
        self.asset_key = asset_key
        self.timeout = timeout

    def report(self, source_ip: str, target: str, method: str = "GET",
               detail: str = "", user_agent: str = "", file_hash: str | None = None) -> bool:
        payload: dict[str, Any] = {
            "source_ip": source_ip, "target": target, "method": method,
            "detail": detail[:4000], "user_agent": user_agent[:1000],
            "file_hash": file_hash,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint, data=body, method="POST",
            headers={"Content-Type": "application/json", "X-Asset-Key": self.asset_key},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError):
            # Telemetry failure must not break the protected application request.
            return False


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
