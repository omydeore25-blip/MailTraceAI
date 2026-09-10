from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class IOCItem(BaseModel):
    ioc_type: str # url, ip, domain, md5, sha1, sha256
    value: str
    defanged_value: str
    reputation_score: float = 0.0 # 0 (clean) to 100 (critical threat)
    is_malicious: bool = False
    enrichment: Dict[str, Any] = {}


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    is_executable_or_script: bool
    is_archive: bool
    is_macro_enabled: bool
    risk_level: str # Low, Medium, High, Critical
    risk_flags: List[str] = []


class ExtractedIOCs(BaseModel):
    urls: List[IOCItem] = []
    ips: List[IOCItem] = []
    domains: List[IOCItem] = []
    attachments: List[AttachmentMeta] = []
    total_iocs_found: int = 0
    malicious_iocs_count: int = 0
