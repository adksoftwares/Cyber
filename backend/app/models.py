from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from .db import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), index=True)
    target = Column(String(512), default="/")
    method = Column(String(12), default="GET")
    category = Column(String(80), default="unclassified", index=True)
    severity = Column(String(16), default="low", index=True)
    detail = Column(Text, default="")
    user_agent = Column(Text, default="")

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(64), unique=True, index=True)
    reason = Column(String(500), default="Manual block")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    active = Column(Boolean, default=True)

class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id = Column(Integer, primary_key=True)
    action = Column(String(100))
    actor = Column(String(100), default="admin")
    detail = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
