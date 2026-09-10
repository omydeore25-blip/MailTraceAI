from typing import Optional, List
from app.services.authentication.spf_verifier import verify_spf
from app.services.authentication.dkim_verifier import verify_dkim
from app.services.authentication.dmarc_verifier import verify_dmarc
from app.services.authentication.arc_verifier import verify_arc
from app.schemas.authentication import AuthSummary


def audit_authentication(
    from_domain: str,
    client_ip: Optional[str] = None,
    raw_headers: str = "",
    raw_message_bytes: Optional[bytes] = None
) -> AuthSummary:
    """Run comprehensive authentication protocol audit across SPF, DKIM, DMARC, and ARC."""
    spf_res = verify_spf(from_domain=from_domain, client_ip=client_ip, raw_headers=raw_headers)
    dkim_res = verify_dkim(from_domain=from_domain, raw_headers=raw_headers, raw_message_bytes=raw_message_bytes)
    dmarc_res = verify_dmarc(from_domain=from_domain, spf_result=spf_res, dkim_result=dkim_res, raw_headers=raw_headers)
    arc_res = verify_arc(raw_headers=raw_headers)

    failure_reasons: List[str] = []
    
    if spf_res.status in ["fail", "softfail", "permerror"]:
        failure_reasons.append(f"SPF Check Failed ({spf_res.status}): IP {client_ip or 'unknown'} not authorized")
    elif not spf_res.aligned and spf_res.status == "pass":
        failure_reasons.append("SPF Unaligned: Evaluated domain differs from From domain")

    if dkim_res.status in ["fail", "invalid"]:
        failure_reasons.append(f"DKIM Signature Failed: {dkim_res.details}")
    elif dkim_res.signature_found and not dkim_res.aligned:
        failure_reasons.append("DKIM Unaligned: DKIM domain does not match From header domain")

    if dmarc_res.status == "fail":
        failure_reasons.append(f"DMARC Policy Violation: Neither SPF nor DKIM passed aligned checks (Policy: {dmarc_res.policy})")

    # Overall authenticity: DMARC pass OR (SPF pass and DKIM pass)
    overall_authenticated = (dmarc_res.status == "pass") or (spf_res.status == "pass" and dkim_res.status == "pass")

    return AuthSummary(
        spf=spf_res,
        dkim=dkim_res,
        dmarc=dmarc_res,
        arc=arc_res,
        overall_authenticated=overall_authenticated,
        failure_reasons=failure_reasons
    )
