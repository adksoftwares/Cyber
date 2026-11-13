from pydantic import BaseModel, Field

class EventIn(BaseModel):
    source_ip: str = Field(min_length=1, max_length=64)
    target: str = Field(default="/", max_length=512)
    method: str = Field(default="GET", max_length=12)
    detail: str = Field(default="", max_length=4000)
    user_agent: str = Field(default="", max_length=1000)

class BlockIn(BaseModel):
    ip_address: str = Field(min_length=3, max_length=64)
    reason: str = Field(default="Manual block", max_length=500)
