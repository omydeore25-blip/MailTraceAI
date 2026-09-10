from typing import List, Dict, Any
from pydantic import BaseModel


class RiskFactor(BaseModel):
    category: str # "Header Forensics", "Authentication", "Threat Intel", "AI Intent", "Payloads"
    weight_percentage: int
    score: float # 0 to 100
    weighted_contribution: float
    description: str
    flagged_items: List[str] = []


class RiskScoreResult(BaseModel):
    overall_score: float # 0 to 100
    threat_level: str # Clean, Suspicious, Malicious, Critical
    summary: str
    factors: List[RiskFactor] = []
    recommended_action: str # Deliver, Quarantine, Strip Attachments, Block Sender & IP
