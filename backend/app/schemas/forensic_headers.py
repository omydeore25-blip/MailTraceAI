from typing import Optional, List, Dict
from pydantic import BaseModel


class ReceivedHop(BaseModel):
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[int] = 0
    anomalous: bool = False
    anomaly_reason: Optional[str] = None
    is_private: bool = False
    geo_status: Optional[str] = None
    geo_error: Optional[str] = None


class HeaderForensicReport(BaseModel):
    subject: Optional[str] = None
    message_id: Optional[str] = None
    date: Optional[str] = None
    from_header: str
    from_name: Optional[str] = None
    from_domain: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    to: List[str] = []
    cc: List[str] = []
    mailer_client: Optional[str] = None # e.g. User-Agent / X-Mailer
    hops: List[ReceivedHop] = []
    spoofing_indicators: List[str] = []
    has_spoofed_headers: bool = False
    total_transit_time_seconds: int = 0
