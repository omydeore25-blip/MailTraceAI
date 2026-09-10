from typing import Optional, Literal
from datetime import datetime
from pydantic import BaseModel, ConfigDict


SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]


class AnalystAlert(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    severity: SeverityLevel
    title: str
    description: str
    evidence: str
    source: str
    related_ioc: Optional[str] = None
    analysis_id: Optional[str] = None
    timestamp: Optional[str] = None
