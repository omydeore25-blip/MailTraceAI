import re
from typing import Optional, Dict, Any
from app.schemas.authentication import DMARCResult, SPFResult, DKIMResult


def verify_dmarc(
    from_domain: str,
    spf_result: SPFResult,
    dkim_result: DKIMResult,
    raw_headers: str = ""
) -> DMARCResult:
    """
    Evaluate DMARC (RFC 7489) using SPF & DKIM alignment and DNS TXT policy records.
    """
    auth_header_match = re.search(r"dmarc=([a-zA-Z]+)(?:\s+\((.*?)\))?", raw_headers, re.IGNORECASE)
    
    status = "none"
    policy = "none"
    record = None
    details = "No DMARC record evaluated"
    pct = 100

    verification_method = "inferred"

    # 1. Attempt DNS TXT lookup for _dmarc.{from_domain}
    if from_domain:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            answers = resolver.resolve(f"_dmarc.{from_domain}", "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=DMARC1"):
                    record = txt_str
                    verification_method = "live_dns"
                    p_match = re.search(r"\bp=([a-zA-Z]+)", txt_str)
                    if p_match:
                        policy = p_match.group(1).lower()
                    pct_match = re.search(r"\bpct=([0-9]+)", txt_str)
                    if pct_match:
                        pct = int(pct_match.group(1))
                    break
        except Exception:
            pass

    # 2. Alignment Logic: RFC 7489
    # DMARC passes if EITHER:
    # (SPF is pass AND SPF domain is aligned) OR (DKIM is pass AND DKIM domain is aligned)
    spf_aligned_pass = (spf_result.status.lower() == "pass") and spf_result.aligned
    dkim_aligned_pass = (dkim_result.status.lower() == "pass") and dkim_result.aligned

    if auth_header_match:
        status = auth_header_match.group(1).lower()
        if auth_header_match.group(2):
            details = auth_header_match.group(2)
        else:
            details = f"Parsed from Authentication-Results: dmarc={status}"
        if record:
            details += f" | Live DNS verified policy record: {record[:60]}"
            verification_method = "live_dns"
        else:
            verification_method = "inferred"
    else:
        if spf_aligned_pass or dkim_aligned_pass:
            status = "pass"
            details = "DMARC passed: " + ("SPF aligned" if spf_aligned_pass else "DKIM aligned")
        else:
            status = "fail" if record else "none"
            details = f"DMARC {status}: Neither SPF nor DKIM passed with domain alignment for '{from_domain}'"

    return DMARCResult(
        status=status,
        policy=policy,
        subdomain_policy=None,
        percentage=pct,
        spf_aligned=spf_aligned_pass,
        dkim_aligned=dkim_aligned_pass,
        record=record,
        details=details,
        verification_method=verification_method
    )

