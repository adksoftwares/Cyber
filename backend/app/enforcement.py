"""Optional Cloudflare IP Access Rules integration.

Only call this adapter for assets/zones the operator owns and has authorized.
When credentials are absent the adapter remains in logging-only mode.
"""
import json
import ipaddress
import logging
import urllib.error
import urllib.request
from .config import settings

log = logging.getLogger("ary.cybershield.firewall")

class EdgeFirewall:
    def __init__(self):
        self.token = settings.cloudflare_api_token
        self.zone_id = settings.cloudflare_zone_id
        self.base = "https://api.cloudflare.com/client/v4"

    @property
    def configured(self):
        return bool(self.token and self.zone_id)

    def _request(self, method, path, payload=None):
        if not self.configured:
            raise RuntimeError("Cloudflare edge enforcement is not configured")
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Cloudflare API returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Cloudflare API request failed: {exc}") from exc
        if not body.get("success"):
            raise RuntimeError("Cloudflare rejected the firewall request")
        return body.get("result")

    def add_deny_rule(self, ip_address: str, reason: str) -> str:
        address = ipaddress.ip_address(ip_address)
        target = "ip" if address.version == 4 else "ip6"
        result = self._request("POST", f"/zones/{self.zone_id}/firewall/access_rules/rules", {
            "mode": "block",
            "configuration": {"target": target, "value": str(address)},
            "notes": (reason or "ARY CyberShield security response")[:500]
        })
        rule_id = result.get("id") if isinstance(result, dict) else None
        if not rule_id:
            raise RuntimeError("Cloudflare did not return a rule identifier")
        log.warning("EDGE_BLOCK_APPLIED ip=%s rule_id=%s", ip_address, rule_id)
        return rule_id

    def remove_deny_rule(self, rule_id: str) -> None:
        if not rule_id:
            raise RuntimeError("No provider rule ID is recorded for this block")
        self._request("DELETE", f"/zones/{self.zone_id}/firewall/access_rules/rules/{rule_id}")
        log.info("EDGE_BLOCK_REMOVED rule_id=%s", rule_id)
