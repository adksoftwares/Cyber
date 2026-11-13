import hashlib
import secrets
from urllib.parse import urlsplit
from fastapi import Depends, FastAPI, Header, HTTPException
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
    block_columns = {c["name"] for c in inspect(engine).get_columns("blocked_ips")}
    if "provider_rule_id" not in block_columns:
        connection.execute(text("ALTER TABLE blocked_ips ADD COLUMN provider_rule_id VARCHAR(160)"))

app = FastAPI(title=settings.app_name, version="0.3.0")
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
    host = urlsplit(payload.target if "://" in payload.target else "//" + payload.target).hostname
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.active.is_(True)).all()
    indicator = next((item for item in indicators if
        (item.indicator_type == "ip" and item.value == source_ip) or
        (item.indicator_type == "domain" and host and (host.lower() == item.value or host.lower().endswith("." + item.value)))), None)
    if indicator:
        category, severity = "threat_intelligence_match", "high"
    event = SecurityEvent(source_ip=source_ip, target=payload.target, method=payload.method.upper(), category=category, severity=severity, detail=payload.detail, user_agent=payload.user_agent, asset_id=asset_id, matched_indicator_id=indicator.id if indicator else None)
    db.add(event); db.commit(); db.refresh(event)
    notify_security_event(event)
    return {"id": event.id, "category": category, "severity": severity, "threat_intelligence_match": bool(indicator), "matched_indicator_type": indicator.indicator_type if indicator else None}

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

@app.get("/api/events", dependencies=[Depends(require_admin)])
def events(limit: int = 100, asset_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(SecurityEvent)
    if asset_id is not None: query = query.filter(SecurityEvent.asset_id == asset_id)
    rows = query.order_by(desc(SecurityEvent.created_at)).limit(max(1, min(limit, 500))).all()
    return [{"id":r.id,"created_at":r.created_at,"source_ip":r.source_ip,"target":r.target,"method":r.method,"category":r.category,"severity":r.severity,"detail":r.detail,"asset_id":r.asset_id,"matched_indicator_id":r.matched_indicator_id} for r in rows]

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
    return [{"ip_address":r.ip_address,"reason":r.reason,"created_at":r.created_at} for r in rows]

@app.post("/api/blocks", dependencies=[Depends(require_admin)])
def block_ip(payload: BlockIn, db: Session = Depends(get_db)):
    try: ip = valid_ip(payload.ip_address)
    except ValueError: raise HTTPException(status_code=422, detail="Invalid IP address")
    row = db.query(BlockedIP).filter_by(ip_address=ip).first()
    if row: row.active=True; row.reason=payload.reason
    else: row=BlockedIP(ip_address=ip, reason=payload.reason); db.add(row)
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
    if row.provider_rule_id:
        try:
            firewall.remove_deny_rule(row.provider_rule_id)
            db.add(AuditEntry(action="edge_unblock_applied", detail=f"ip={ip};provider=cloudflare"))
            row.provider_rule_id = None
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Edge provider could not remove the rule: {str(exc)[:300]}")
    row.active=False; db.add(AuditEntry(action="unblock_ip", detail=ip)); db.commit()
    return {"blocked": False, "ip_address": ip, "enforcement": "provider_rule_removed" if not row.active and not row.provider_rule_id else "record_only"}

@app.get("/api/audit", dependencies=[Depends(require_admin)])
def audit(limit: int = 100, db: Session = Depends(get_db)):
    rows=db.query(AuditEntry).order_by(desc(AuditEntry.created_at)).limit(max(1,min(limit,500))).all()
    return [{"id":r.id,"action":r.action,"actor":r.actor,"detail":r.detail,"created_at":r.created_at} for r in rows]
