from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from .config import settings
from .db import Base, engine, get_db
from .models import SecurityEvent, BlockedIP, AuditEntry
from .schemas import EventIn, BlockIn
from .security import classify, valid_ip
from .middleware import SecurityMiddleware
from .health import dependency_status
from .alerts import notify_security_event
from .enforcement import LoggingOnlyFirewall

Base.metadata.create_all(bind=engine)
app = FastAPI(title=settings.app_name, version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-Admin-Key", "X-Ingest-Key"])
app.add_middleware(SecurityMiddleware, limit=120, window_seconds=60)
firewall = LoggingOnlyFirewall()

def require_admin(x_admin_key: str | None = Header(default=None)):
    if not x_admin_key or x_admin_key != settings.admin_key:
        raise HTTPException(status_code=401, detail="Invalid admin key")

def require_ingest(x_ingest_key: str | None = Header(default=None)):
    if not x_ingest_key or x_ingest_key != settings.ingest_key:
        raise HTTPException(status_code=401, detail="Invalid ingest key")

@app.get("/health")
def health():
    dependencies = dependency_status()
    return {"status": "ok" if dependencies["database"] == "ok" else "degraded",
            "service": settings.app_name, "dependencies": dependencies}

@app.post("/api/events", dependencies=[Depends(require_ingest)])
def ingest_event(payload: EventIn, db: Session = Depends(get_db)):
    try:
        source_ip = valid_ip(payload.source_ip)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address")
    category, severity = classify(payload.target, payload.detail)
    event = SecurityEvent(source_ip=source_ip, target=payload.target,
        method=payload.method.upper(), category=category, severity=severity,
        detail=payload.detail, user_agent=payload.user_agent)
    db.add(event); db.commit(); db.refresh(event)
    notify_security_event(event)
    return {"id": event.id, "category": category, "severity": severity}

@app.get("/api/summary", dependencies=[Depends(require_admin)])
def summary(db: Session = Depends(get_db)):
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0
    high = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.severity == "high").scalar() or 0
    blocked = db.query(func.count(BlockedIP.id)).filter(BlockedIP.active.is_(True)).scalar() or 0
    return {"events": total, "high_severity": high, "blocked_ips": blocked}

@app.get("/api/events", dependencies=[Depends(require_admin)])
def events(limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.query(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit).all()
    return [{"id":r.id,"created_at":r.created_at,"source_ip":r.source_ip,
        "target":r.target,"method":r.method,"category":r.category,
        "severity":r.severity,"detail":r.detail} for r in rows]

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
    firewall.add_deny_rule(ip, payload.reason)
    return {"blocked": True, "ip_address": ip, "enforcement": "logged_only"}

@app.delete("/api/blocks/{ip_address}", dependencies=[Depends(require_admin)])
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    try: ip = valid_ip(ip_address)
    except ValueError: raise HTTPException(status_code=422, detail="Invalid IP address")
    row=db.query(BlockedIP).filter_by(ip_address=ip).first()
    if not row: raise HTTPException(status_code=404, detail="IP not found")
    row.active=False; db.add(AuditEntry(action="unblock_ip", detail=ip)); db.commit()
    firewall.remove_deny_rule(ip)
    return {"blocked": False, "ip_address": ip, "enforcement": "logged_only"}

@app.get("/api/audit", dependencies=[Depends(require_admin)])
def audit(limit: int = 100, db: Session = Depends(get_db)):
    rows=db.query(AuditEntry).order_by(desc(AuditEntry.created_at)).limit(max(1,min(limit,500))).all()
    return [{"id":r.id,"action":r.action,"actor":r.actor,"detail":r.detail,"created_at":r.created_at} for r in rows]
