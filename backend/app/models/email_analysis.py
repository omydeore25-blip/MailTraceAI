import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    sender: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    from_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reply_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    return_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recipients: Mapped[List[str]] = mapped_column(JSON, default=list)
    email_date: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Forensic payloads & parsed data
    raw_headers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_plain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Analysis & Risk
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    threat_level: Mapped[str] = mapped_column(String(50), default="Clean", index=True) # Clean, Suspicious, Malicious, Critical
    risk_breakdown: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Protocol Authentication (SPF, DKIM, DMARC, ARC)
    auth_results: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Hop chain & Timeline
    hop_timeline: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    
    # Attachments Metadata
    attachments_meta: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    
    # AI & Attribution
    ai_insights: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    mitre_attack: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Metadata
    analyzed_by_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    iocs = relationship("IOC", back_populates="analysis", cascade="all, delete-orphan")
