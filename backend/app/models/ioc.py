import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, DateTime, JSON, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("email_analyses.id"), index=True, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False) # url, ip, domain, md5, sha256
    value: Mapped[str] = mapped_column(String(1000), index=True, nullable=False)
    defanged_value: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    
    # Intelligence Data
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0) # 0 to 100
    is_malicious: Mapped[bool] = mapped_column(default=False)
    enrichment_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    analysis = relationship("EmailAnalysis", back_populates="iocs")
