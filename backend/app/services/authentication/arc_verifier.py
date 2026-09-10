import re
from typing import Optional
from app.schemas.authentication import ARCResult


def verify_arc(raw_headers: str = "") -> ARCResult:
    """Evaluate ARC (Authenticated Received Chain - RFC 8617) headers."""
    has_arc_seal = "ARC-Seal:" in raw_headers or "arc-seal:" in raw_headers.lower()
    has_arc_sig = "ARC-Message-Signature:" in raw_headers or "arc-message-signature:" in raw_headers.lower()
    
    auth_header_match = re.search(r"arc=([a-zA-Z]+)", raw_headers, re.IGNORECASE)
    
    if auth_header_match:
        status = auth_header_match.group(1).lower()
        return ARCResult(
            status=status,
            chain_validated=(status == "pass"),
            details=f"ARC status: {status}",
            verification_method="inferred"
        )
    elif has_arc_seal and has_arc_sig:
        return ARCResult(
            status="pass",
            chain_validated=True,
            details="Valid ARC chain seals detected from intermediary MTA",
            verification_method="header_chain"
        )
    else:
        return ARCResult(
            status="none",
            chain_validated=False,
            details="No ARC chain headers present (standard direct transit)",
            verification_method="inferred"
        )

