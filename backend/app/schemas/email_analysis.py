from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.schemas.forensic_headers import HeaderForensicReport, ReceivedHop
from app.schemas.authentication import AuthSummary
from app.schemas.ioc import ExtractedIOCs, AttachmentMeta
from app.schemas.risk import RiskScoreResult
from app.schemas.alert import AnalystAlert
from app.schemas.graph import GraphData


class EmailAnalysisCreateRequest(BaseModel):
    raw_email_text: Optional[str] = None


class EmailAnalysisOverview(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: str
    from_name: Optional[str] = None
    email_date: Optional[str] = None
    risk_score: float
    threat_level: str
    campaign_id: Optional[str] = None
    threat_actor: Optional[str] = None
    created_at: datetime


class EmailAnalysisDetail(EmailAnalysisOverview):
    recipients: List[str] = []
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    raw_headers: Optional[str] = None
    
    # Forensic Sub-structures
    headers_report: Optional[HeaderForensicReport] = None
    auth_summary: Optional[AuthSummary] = None
    extracted_iocs: Optional[ExtractedIOCs] = None
    risk_assessment: Optional[RiskScoreResult] = None
    ai_insights: Dict[str, Any] = {}
    mitre_attack: List[Dict[str, Any]] = []
    
    # Timeline
    hops: List[ReceivedHop] = []
    
    # Attachments
    attachments: List[AttachmentMeta] = []
    
    # Real-Time Analyst Alerts & Graph
    alerts: List[AnalystAlert] = []
    graph: Optional[GraphData] = None
