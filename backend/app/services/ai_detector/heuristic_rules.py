import re
from typing import Dict, Any, List

URGENCY_PATTERNS = [
    r"\bimmediat(?:e|ely)\b",
    r"\baction required\b",
    r"\bwithin 24 hours\b",
    r"\baccount (?:will be )?suspended\b",
    r"\bdeactivat(?:ed|ion)\b",
    r"\burgent(?:ly)?\b",
    r"\bfailure to respond\b",
    r"\bfinal notice\b",
    r"\bsecurity alert\b",
    r"\bterminated\b"
]

FINANCIAL_BEC_PATTERNS = [
    r"\bwire transfer\b",
    r"\bdirect deposit\b",
    r"\bpayroll update\b",
    r"\boverdue invoice\b",
    r"\bpayment details\b",
    r"\bgift card\b",
    r"\bswift code\b",
    r"\bbank routing\b",
    r"\bvendor payment\b",
    r"\bremit(?:tance)?\b"
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"\bverify your account\b",
    r"\bupdate your password\b",
    r"\bpassword reset\b",
    r"\bconfirm your identity\b",
    r"\bclick here to log ?in\b",
    r"\bsign in to (?:verify|continue)\b",
    r"\b2fa verification\b",
    r"\bmicrosoft (?:365|office) login\b",
    r"\bsession expired\b"
]

AUTHORITY_PATTERNS = [
    r"\bconfidential\b",
    r"\bdo not disclose\b",
    r"\bexecutive office\b",
    r"\bdirected by the ceo\b",
    r"\baudit compliance\b"
]


def extract_linguistic_heuristics(subject: str, plain_body: str, html_body: str) -> Dict[str, Any]:
    """Scan text for social engineering, urgency, financial fraud, and credential harvesting patterns."""
    text = f"{subject} {plain_body} {html_body}".lower()

    matched_urgency = [p for p in URGENCY_PATTERNS if re.search(p, text)]
    matched_financial = [p for p in FINANCIAL_BEC_PATTERNS if re.search(p, text)]
    matched_credentials = [p for p in CREDENTIAL_HARVEST_PATTERNS if re.search(p, text)]
    matched_authority = [p for p in AUTHORITY_PATTERNS if re.search(p, text)]

    urgency_score = min(100.0, len(matched_urgency) * 25.0)
    financial_score = min(100.0, len(matched_financial) * 35.0)
    credential_score = min(100.0, len(matched_credentials) * 35.0)
    authority_score = min(100.0, len(matched_authority) * 25.0)

    # Composite heuristic score
    composite_heuristic = min(100.0, (
        (urgency_score * 0.25) +
        (financial_score * 0.35) +
        (credential_score * 0.30) +
        (authority_score * 0.10)
    ))

    # All triggers
    all_triggers = (
        [f"Urgency: {re.sub(r'[^a-zA-Z0-9 ]', '', p).strip()}" for p in matched_urgency] +
        [f"Financial/BEC: {re.sub(r'[^a-zA-Z0-9 ]', '', p).strip()}" for p in matched_financial] +
        [f"Credential Harvest: {re.sub(r'[^a-zA-Z0-9 ]', '', p).strip()}" for p in matched_credentials] +
        [f"Authority/Coercion: {re.sub(r'[^a-zA-Z0-9 ]', '', p).strip()}" for p in matched_authority]
    )

    return {
        "heuristic_score": composite_heuristic,
        "urgency_score": urgency_score,
        "financial_score": financial_score,
        "credential_score": credential_score,
        "authority_score": authority_score,
        "triggered_patterns": all_triggers
    }
