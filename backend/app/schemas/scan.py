import re
from datetime import datetime
from pydantic import BaseModel, field_validator
from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    target: str
    client_id: int | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        # Accept IP or CIDR — each octet bounded 0-255, prefix bounded 0-32.
        octet = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        pattern = rf"^({octet}\.){{3}}{octet}(\/(3[0-2]|[12]?\d))?$"
        if not re.match(pattern, v):
            raise ValueError("Invalid IP or CIDR notation")
        return v


class PortOut(BaseModel):
    model_config = {"from_attributes": True}
    port_number: int
    protocol: str
    service: str | None
    version: str | None
    state: str


class HostOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    ip: str
    hostname: str | None
    os: str | None
    ports: list[PortOut] = []


class ScanOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    target: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None
    client_id: int | None = None
    hosts: list[HostOut] = []
