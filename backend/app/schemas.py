from pydantic import BaseModel, Field, field_validator
from typing import Literal

class EventIn(BaseModel):
    source_ip: str = Field(min_length=1, max_length=64)
    target: str = Field(default="/", max_length=512)
    method: str = Field(default="GET", max_length=12)
    detail: str = Field(default="", max_length=4000)
    user_agent: str = Field(default="", max_length=1000)
    file_hash: str | None = Field(default=None, min_length=64, max_length=64)

    @field_validator("file_hash")
    @classmethod
    def validate_file_hash(cls, value):
        if value is None:
            return None
        import re
        value = value.strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("file_hash must be a SHA-256 hexadecimal digest")
        return value

class BlockIn(BaseModel):
    ip_address: str = Field(min_length=3, max_length=64)
    reason: str = Field(default="Manual block", max_length=500)

class AssetIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    base_url: str = Field(default="", max_length=500)
    asset_type: Literal["website", "api", "application", "database", "admin_panel", "other"] = "website"
    description: str = Field(default="", max_length=2000)

class IndicatorIn(BaseModel):
    indicator_type: Literal["ip", "domain", "sha256"]
    value: str = Field(min_length=1, max_length=255)
    source: str = Field(default="manual", max_length=160)
    confidence: int = Field(default=50, ge=0, le=100)
    notes: str = Field(default="", max_length=1000)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value, info):
        kind = info.data.get("indicator_type")
        value = value.strip().lower()
        if kind == "ip":
            import ipaddress
            return str(ipaddress.ip_address(value))
        if kind == "sha256":
            import re
            if not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError("SHA-256 indicators must be 64 hexadecimal characters")
        if kind == "domain":
            import re
            if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}", value):
                raise ValueError("Invalid domain indicator")
        return value
