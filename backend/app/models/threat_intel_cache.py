import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy import String, DateTime, JSON, Float, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        UniqueConstraint("ioc_type", "ioc_value", name="uix_ioc_type_value"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False) # ip, url, domain, sha256
    ioc_value: Mapped[str] = mapped_column(String(1000), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False) # virustotal, abuseipdb, ipinfo, mock
    
    score: Mapped[float] = mapped_column(Float, default=0.0)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    cached_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
