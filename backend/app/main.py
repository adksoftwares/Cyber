import hashlib
import csv
import io
import json
import ipaddress
import re
import urllib.error
import urllib.request
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, inspect, text
from .config import settings
from .db import Base, engine, get_db
from .models import SecurityEvent, BlockedIP, AuditEntry, ProtectedAsset, ThreatIndicator
from .schemas import EventIn, BlockIn, AssetIn, IndicatorIn
from .security import classify, valid_ip
from .middleware import SecurityMiddleware
from .health import dependency_status
from .alerts import notify_security_event
from .enforcement import EdgeFirewall

Base.metadata.create_all(bind=engine)
with engine.begin() as connection:
    columns = {c["name"] for c in inspect(engine).get_columns("security_events")}
    if "asset_id" not in columns:
        connection.execute(text("ALTER TABLE security_events ADD COLUMN asset_id INTEGER"))
    if "matched_indicator_id" not in columns:
        connection.execute(text("ALTER TABLE security_events ADD COLUMN matched_indicator_id INTEGER"))
    if "file_hash" not in columns:
        connection.execute(text("ALTER TABLE security_events ADD COLUMN file_hash VARCHAR(64)"))
    block_columns = {c["name"] for c in inspect(engine).get_columns("blocked_ips")}
    if "provider_rule_id" not in block_columns:
        connection.execute(text("ALTER TABLE blocked_ips ADD COLUMN provider_rule_id VARCHAR(160)"))

app = FastAPI(title=settings.app_name, version="0.4.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-Admin-Key", "X-Ingest-Key", "X-Asset-Key"])
app.add_middleware(SecurityMiddleware, limit=120, window_seconds=60)
firewall = EdgeFirewall()

def require_admin(x_admin_key: str | None = Header(default=None)):
    if not x_admin_key or not secrets.compare_digest(x_admin_key, settings.admin_key):
        raise HTTPException(status_code=401, detail="Invalid admin key")

def require_ingest(x_ingest_key: str | None = Header(default=None)):
    if not x_ingest_key or not secrets.compare_digest(x_ingest_key, settings.ingest_key):
        raise HTTPException(status_code=401, detail="Invalid ingest key")

def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

@app.get("/health")
def health():
    dependencies = dependency_status()
    return {"status": "ok" if dependencies["database"] == "ok" else "degraded", "service": settings.app_name, "dependencies": dependencies}

def save_event(payload: EventIn, db: Session, asset_id=None):
    try:
        source_ip = valid_ip(payload.source_ip)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address")
    category, severity = classify(payload.target, payload.detail)
    try:
        host = urlsplit(payload.target if "://" in payload.target else "//" + payload.target).hostname
    except ValueError:
        host = None
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.active.is_(True)).all()
    indicator = next((item for item in indicators if
        (item.indicator_type == "ip" and item.value == source_ip) or
        (item.indicator_type == "domain" and host and (host.lower() == item.value or host.lower().endswith("." + item.value))) or
        (item.indicator_type == "sha256" and payload.file_hash and item.value == payload.file_hash)), None)
    if indicator:
        category, severity = "threat_intelligence_match", "high"
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    recent_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.source_ip == source_ip, SecurityEvent.created_at >= cutoff).scalar() or 0
    if recent_count >= 59 and severity != "high":
        category, severity = "traffic_rate_anomaly", "high"
    event = SecurityEvent(source_ip=source_ip, target=payload.target, method=payload.method.upper(), category=category, severity=severity, detail=payload.detail, user_agent=payload.user_agent, asset_id=asset_id, matched_indicator_id=indicator.id if indicator else None, file_hash=payload.file_hash)
    db.add(event); db.commit(); db.refresh(event)
    notify_security_event(event)
    return {"id": event.id, "category": category, "severity": severity, "threat_intelligence_match": bool(indicator), "matched_indicator_type": indicator.indicator_type if indicator else None, "rate_anomaly": category == "traffic_rate_anomaly"}

@app.post("/api/events", dependencies=[Depends(require_ingest)])
def ingest_event(payload: EventIn, db: Session = Depends(get_db)):
    return save_event(payload, db)

@app.post("/api/assets/{asset_id}/events")
def ingest_asset_event(asset_id: int, payload: EventIn, x_asset_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not x_asset_key:
        raise HTTPException(status_code=401, detail="Missing asset key")
    asset = db.query(ProtectedAsset).filter_by(id=asset_id, active=True).first()
    if not asset or not secrets.compare_digest(asset.ingest_token_hash, token_hash(x_asset_key)):
        raise HTTPException(status_code=401, detail="Invalid asset credentials")
    return save_event(payload, db, asset_id=asset.id)

@app.get("/api/summary", dependencies=[Depends(require_admin)])
def summary(db: Session = Depends(get_db)):
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0
    high = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.severity == "high").scalar() or 0
    blocked = db.query(func.count(BlockedIP.id)).filter(BlockedIP.active.is_(True)).scalar() or 0
    assets = db.query(func.count(ProtectedAsset.id)).filter(ProtectedAsset.active.is_(True)).scalar() or 0
    indicators = db.query(func.count(ThreatIndicator.id)).filter(ThreatIndicator.active.is_(True)).scalar() or 0
    return {"events": total, "high_severity": high, "blocked_ips": blocked, "protected_assets": assets, "active_indicators": indicators}

@app.get("/api/analytics/traffic", dependencies=[Depends(require_admin)])
def traffic_analytics(minutes: int = 5, db: Session = Depends(get_db)):
    minutes = max(1, min(minutes, 60))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = db.query(SecurityEvent.source_ip, func.count(SecurityEvent.id).label("event_count")).filter(SecurityEvent.created_at >= cutoff).group_by(SecurityEvent.source_ip).order_by(desc("event_count")).limit(20).all()
    return {"window_minutes": minutes, "sources": [{"source_ip": ip, "events": count} for ip, count in rows]}

@app.get("/api/events/export", dependencies=[Depends(require_admin)])
def export_events(limit: int = 5000, db: Session = Depends(get_db)):
    rows = db.query(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(max(1, min(limit, 10000))).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "source_ip", "asset_id", "method", "target", "category", "severity", "detail", "file_hash"])
    def safe_cell(value):
        text_value = "" if value is None else str(value)
        return "'" + text_value if text_value.startswith(("=", "+", "-", "@", "\t", "\r")) else text_value
    for row in rows:
        writer.writerow([safe_cell(value) for value in (row.id, row.created_at, row.source_ip, row.asset_id, row.method, row.target, row.category, row.severity, row.detail, row.file_hash)])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ary-cybershield-events.csv"})

@app.get("/api/events", dependencies=[Depends(require_admin)])
def events(limit: int = 100, asset_id: int | None = None, severity: str | None = None, db: Session = Depends(get_db)):
    query = db.query(SecurityEvent)
    if asset_id is not None: query = query.filter(SecurityEvent.asset_id == asset_id)
    if severity in ("low", "medium", "high"): query = query.filter(SecurityEvent.severity == severity)
    rows = query.order_by(desc(SecurityEvent.created_at)).limit(max(1, min(limit, 500))).all()
    return [{"id":r.id,"created_at":r.created_at,"source_ip":r.source_ip,"target":r.target,"method":r.method,"category":r.category,"severity":r.severity,"detail":r.detail,"asset_id":r.asset_id,"matched_indicator_id":r.matched_indicator_id,"file_hash":r.file_hash} for r in rows]

@app.get("/api/assets", dependencies=[Depends(require_admin)])
def list_assets(db: Session = Depends(get_db)):
    rows = db.query(ProtectedAsset).order_by(desc(ProtectedAsset.created_at)).all()
    return [{"id":a.id,"name":a.name,"base_url":a.base_url,"asset_type":a.asset_type,"description":a.description,"active":a.active,"created_at":a.created_at} for a in rows]

@app.post("/api/assets", dependencies=[Depends(require_admin)])
def create_asset(payload: AssetIn, db: Session = Depends(get_db)):
    raw_token = secrets.token_urlsafe(32)
    asset = ProtectedAsset(name=payload.name, base_url=payload.base_url, asset_type=payload.asset_type, description=payload.description, ingest_token_hash=token_hash(raw_token))
    db.add(asset); db.flush()
    db.add(AuditEntry(action="create_protected_asset", detail=f"asset_id={asset.id};name={asset.name}"))
    db.commit(); db.refresh(asset)
    return {"id":asset.id,"name":asset.name,"asset_key":raw_token,"ingest_endpoint":f"/api/assets/{asset.id}/events","warning":"Copy this key now; it is only returned once."}

@app.delete("/api/assets/{asset_id}", dependencies=[Depends(require_admin)])
def deactivate_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(ProtectedAsset).filter_by(id=asset_id).first()
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    asset.active = False
    db.add(AuditEntry(action="deactivate_protected_asset", detail=f"asset_id={asset_id}")); db.commit()
    return {"deactivated":True,"asset_id":asset_id}

@app.post("/api/intel/otx/sync", dependencies=[Depends(require_admin)])
def sync_otx_indicators(db: Session = Depends(get_db)):
    """Import a bounded set of subscribed OTX indicators; never auto-block feed entries."""
    if not settings.otx_api_key:
        raise HTTPException(status_code=503, detail="OTX_API_KEY is not configured")
    added = updated = skipped = pulses_seen = processed = 0
    for page in range(1, 4):
        request = urllib.request.Request(
            f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={page}",
            headers={"X-OTX-API-KEY": settings.otx_api_key, "Accept": "application/json", "User-Agent": "ARY-CyberShield/0.4"}
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise HTTPException(status_code=502, detail="OTX response exceeded the 2 MB safety limit")
            payload = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"OTX returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"OTX feed request failed: {str(exc)[:200]}") from exc
        pulses = payload.get("results", [])
        pulses_seen += len(pulses)
        for pulse in pulses:
            pulse_name = str(pulse.get("name") or "OTX subscribed pulse")[:150]
            for raw_indicator in pulse.get("indicators", []):
                if processed >= 1000:
                    break
                processed += 1
                raw_type = str(raw_indicator.get("type") or "").lower()
                value = str(raw_indicator.get("indicator") or "").strip().lower()
                kind = None
                if raw_type in ("ipv4", "ipv6", "ip"):
                    try:
                        value = str(ipaddress.ip_address(value)); kind = "ip"
                    except ValueError:
                        pass
                elif raw_type in ("domain", "hostname"):
                    value = value.rstrip(".")
                    if len(value) <= 253 and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}", value):
                        kind = "domain"
                elif raw_type in ("sha256", "filehash-sha256", "file_hash_sha256"):
                    if re.fullmatch(r"[a-f0-9]{64}", value):
                        kind = "sha256"
                if not kind:
                    skipped += 1
                    continue
                item = db.query(ThreatIndicator).filter_by(indicator_type=kind, value=value).first()
                if item:
                    item.active = True
                    item.source = "OTX: " + pulse_name
                    item.confidence = max(item.confidence or 0, 60)
                    updated += 1
                else:
                    db.add(ThreatIndicator(indicator_type=kind, value=value, source="OTX: " + pulse_name, confidence=60, notes="Imported from subscribed OTX pulse; review context before response."))
                    added += 1
        db.commit()
        if processed >= 1000 or not payload.get("next"):
            break
    db.add(AuditEntry(action="sync_otx_indicators", detail=f"added={added};updated={updated};skipped={skipped};pulses={pulses_seen}"))
    db.commit()
    return {"source": "AlienVault OTX subscribed pulses", "pages_limit": 3, "indicators_limit": 1000, "indicators_processed": processed, "pulses_seen": pulses_seen, "added": added, "updated": updated, "skipped_unsupported_or_invalid": skipped, "auto_blocked": 0, "note": "Community threat indicators can be noisy. Matches raise alerts only; they are never auto-blocked."}

@app.get("/api/indicators", dependencies=[Depends(require_admin)])
def list_indicators(limit: int = 200, db: Session = Depends(get_db)):
    rows = db.query(ThreatIndicator).order_by(desc(ThreatIndicator.created_at)).limit(max(1,min(limit,500))).all()
    return [{"id":i.id,"indicator_type":i.indicator_type,"value":i.value,"source":i.source,"confidence":i.confidence,"notes":i.notes,"active":i.active,"created_at":i.created_at} for i in rows]

@app.post("/api/indicators", dependencies=[Depends(require_admin)])
def add_indicator(payload: IndicatorIn, db: Session = Depends(get_db)):
    existing = db.query(ThreatIndicator).filter_by(indicator_type=payload.indicator_type,value=payload.value).first()
    if existing:
        existing.active=True; existing.source=payload.source; existing.confidence=payload.confidence; existing.notes=payload.notes
        item=existing
    else:
        item=ThreatIndicator(**payload.model_dump()); db.add(item)
    db.add(AuditEntry(action="add_threat_indicator",detail=f"{payload.indicator_type}:{payload.value}"))
    db.commit(); db.refresh(item)
    return {"id":item.id,"indicator_type":item.indicator_type,"value":item.value,"active":item.active}

@app.delete("/api/indicators/{indicator_id}", dependencies=[Depends(require_admin)])
def deactivate_indicator(indicator_id: int, db: Session = Depends(get_db)):
    item=db.query(ThreatIndicator).filter_by(id=indicator_id).first()
    if not item: raise HTTPException(status_code=404,detail="Indicator not found")
    item.active=False; db.add(AuditEntry(action="deactivate_threat_indicator",detail=f"indicator_id={indicator_id}")); db.commit()
    return {"deactivated":True,"indicator_id":indicator_id}

@app.get("/api/blocks", dependencies=[Depends(require_admin)])
def list_blocks(db: Session = Depends(get_db)):
    rows = db.query(BlockedIP).filter(BlockedIP.active.is_(True)).order_by(desc(BlockedIP.created_at)).all()
    return [{"ip_address":r.ip_address,"reason":r.reason,"created_at":r.created_at,"provider_enforced":bool(r.provider_rule_id)} for r in rows]

@app.post("/api/blocks", dependencies=[Depends(require_admin)])
def block_ip(payload: BlockIn, db: Session = Depends(get_db)):
    try: ip = valid_ip(payload.ip_address)
    except ValueError: raise HTTPException(status_code=422, detail="Invalid IP address")
    row = db.query(BlockedIP).filter_by(ip_address=ip).first()
    if row: row.active=True; row.reason=payload.reason
    else: row=BlockedIP(ip_address=ip, reason=payload.reason); db.add(row)
    if row.active and row.provider_rule_id:
        return {"blocked": True, "ip_address": ip, "enforcement": "cloudflare", "provider_rule_id": row.provider_rule_id, "already_enforced": True}
    db.add(AuditEntry(action="block_ip", detail=ip)); db.commit()
    try:
        provider_rule_id = firewall.add_deny_rule(ip, payload.reason)
        row.provider_rule_id = provider_rule_id
        db.add(AuditEntry(action="edge_block_applied", detail=f"ip={ip};provider=cloudflare"))
        db.commit()
        return {"blocked": True, "ip_address": ip, "enforcement": "cloudflare", "provider_rule_id": provider_rule_id}
    except Exception as exc:
        db.add(AuditEntry(action="edge_block_not_applied", detail=f"ip={ip};error={str(exc)[:300]}"))
        db.commit()
        return {"blocked": True, "ip_address": ip, "enforcement": "not_applied", "warning": str(exc)}

@app.delete("/api/blocks/{ip_address}", dependencies=[Depends(require_admin)])
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    try: ip = valid_ip(ip_address)
    except ValueError: raise HTTPException(status_code=422, detail="Invalid IP address")
    row=db.query(BlockedIP).filter_by(ip_address=ip).first()
    if not row: raise HTTPException(status_code=404, detail="IP not found")
    removed_provider_rule = False
    if row.provider_rule_id:
        try:
            firewall.remove_deny_rule(row.provider_rule_id)
            removed_provider_rule = True
            db.add(AuditEntry(action="edge_unblock_applied", detail=f"ip={ip};provider=cloudflare"))
            row.provider_rule_id = None
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Edge provider could not remove the rule: {str(exc)[:300]}")
    row.active=False; db.add(AuditEntry(action="unblock_ip", detail=ip)); db.commit()
    return {"blocked": False, "ip_address": ip, "enforcement": "provider_rule_removed" if removed_provider_rule else "record_only"}

@app.get("/api/audit", dependencies=[Depends(require_admin)])
def audit(limit: int = 100, db: Session = Depends(get_db)):
    rows=db.query(AuditEntry).order_by(desc(AuditEntry.created_at)).limit(max(1,min(limit,500))).all()
    return [{"id":r.id,"action":r.action,"actor":r.actor,"detail":r.detail,"created_at":r.created_at} for r in rows]
