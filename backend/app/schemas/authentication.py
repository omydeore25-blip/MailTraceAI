from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class SPFResult(BaseModel):
    status: str # pass, fail, softfail, neutral, none, temperror, permerror, unknown
    record: Optional[str] = None
    client_ip: Optional[str] = None
    evaluated_domain: Optional[str] = None
    aligned: bool = False
    details: Optional[str] = None
    verification_method: str = "inferred" # "live_dns" or "inferred"


class DKIMResult(BaseModel):
    status: str # pass, fail, neutral, none, invalid, temperror, permerror
    selector: Optional[str] = None
    domain: Optional[str] = None
    algorithm: Optional[str] = None
    aligned: bool = False
    signature_found: bool = False
    details: Optional[str] = None
    verification_method: str = "inferred" # "live_dns_crypto" or "inferred"


class DMARCResult(BaseModel):
    status: str # pass, fail, none, temperror, permerror
    policy: Optional[str] = None # none, quarantine, reject
    subdomain_policy: Optional[str] = None
    percentage: Optional[int] = 100
    spf_aligned: bool = False
    dkim_aligned: bool = False
    record: Optional[str] = None
    details: Optional[str] = None
    verification_method: str = "inferred" # "live_dns" or "inferred"


class ARCResult(BaseModel):
    status: str # pass, fail, none
    chain_validated: bool = False
    details: Optional[str] = None
    verification_method: str = "inferred" # "header_chain" or "inferred"


class AuthSummary(BaseModel):
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    arc: ARCResult
    overall_authenticated: bool
    failure_reasons: List[str] = []
