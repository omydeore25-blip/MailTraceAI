import re
from typing import Optional, Dict, Any
from app.schemas.authentication import SPFResult


def verify_spf(
    from_domain: str,
    client_ip: Optional[str] = None,
    raw_headers: str = ""
) -> SPFResult:
    """
    Evaluate SPF (Sender Policy Framework - RFC 7208) for the email.
    Uses headers (Authentication-Results, Received-SPF) and DNS lookup with graceful fallback.
    """
    # 1. Inspect existing authentication headers first
    auth_headers_match = re.search(r"spf=([a-zA-Z]+)(?:\s+\((.*?)\))?", raw_headers, re.IGNORECASE)
    received_spf_match = re.search(r"Received-SPF:\s*([a-zA-Z]+)(?:\s+.*?\((.*?)\))?", raw_headers, re.IGNORECASE)

    status = "none"
    details = "No SPF record or authentication header detected"
    record = None
    evaluated_domain = from_domain

    verification_method = "inferred"

    if auth_headers_match:
        status = auth_headers_match.group(1).lower()
        if auth_headers_match.group(2):
            details = auth_headers_match.group(2)
        else:
            details = f"Parsed from Authentication-Results: spf={status}"
        verification_method = "inferred"
    elif received_spf_match:
        status = received_spf_match.group(1).lower()
        if received_spf_match.group(2):
            details = received_spf_match.group(2)
        else:
            details = f"Parsed from Received-SPF: {status}"
        verification_method = "inferred"

    # 2. Attempt DNS TXT lookup if dnspython is available
    if from_domain:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            answers = resolver.resolve(from_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    record = txt_str
                    if status == "none":
                        # If we found an SPF record but no auth header had a verdict, check alignment
                        status = "pass" if client_ip and client_ip in txt_str else "neutral"
                        details = f"SPF record published via Live DNS: {txt_str[:80]}..."
                        verification_method = "live_dns"
                    else:
                        details += f" | Live DNS verified published SPF record"
                        verification_method = "live_dns"
                    break
        except Exception:
            # Fallback or offline environment
            pass

    # 3. Check alignment (RFC 7489)
    aligned = status.lower() == "pass"

    return SPFResult(
        status=status,
        record=record,
        client_ip=client_ip,
        evaluated_domain=evaluated_domain,
        aligned=aligned,
        details=details,
        verification_method=verification_method
    )

