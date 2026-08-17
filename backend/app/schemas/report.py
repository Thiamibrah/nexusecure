from datetime import datetime
from pydantic import BaseModel


class ReportOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_id: int
    pdf_path: str | None
    risk_score: float
    created_at: datetime
