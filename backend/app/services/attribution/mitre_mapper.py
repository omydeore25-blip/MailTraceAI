import json
import os
from typing import List, Dict, Any
from app.schemas.ioc import ExtractedIOCs
from app.schemas.forensic_headers import HeaderForensicReport
from app.schemas.authentication import AuthSummary

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "mitre_attack_rules.json")


def map_mitre_attack_techniques(
    headers_report: HeaderForensicReport,
    auth_summary: AuthSummary,
    iocs: ExtractedIOCs,
    ai_intent: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Map detected indicators to MITRE ATT&CK Enterprise Matrix techniques."""
    matched_techniques: List[Dict[str, Any]] = []

    # Check for Spearphishing Attachment (T1566.001)
    has_dangerous_att = any(a.risk_level in ["High", "Critical"] for a in iocs.attachments)
    has_any_att = len(iocs.attachments) > 0

    if has_dangerous_att:
        matched_techniques.append({
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "confidence": "High",
            "evidence": f"Weaponized payload identified: {', '.join(a.filename for a in iocs.attachments if a.risk_level in ['High', 'Critical'])}"
        })
        matched_techniques.append({
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "confidence": "Medium",
            "evidence": "Requires recipient interaction to execute payload."
        })

    # Check for Spearphishing Link (T1566.002)
    has_malicious_url = any(u.is_malicious or u.reputation_score > 50 for u in iocs.urls)
    if has_malicious_url or (len(iocs.urls) > 0 and ai_intent.get("primary_category") == "Credential Harvesting Phishing"):
        matched_techniques.append({
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "confidence": "High" if has_malicious_url else "Medium",
            "evidence": f"Deceptive or malicious links discovered: {', '.join(u.defanged_value for u in iocs.urls[:3])}"
        })
        matched_techniques.append({
            "id": "T1598.003",
            "name": "Phishing for Information: Hyperlink",
            "tactic": "Reconnaissance",
            "confidence": "High",
            "evidence": "Targeted link designed to elicit authentication credentials or internal records."
        })

    # Check for Compromised Relay / Valid Accounts (T1078)
    if headers_report.has_spoofed_headers or not auth_summary.overall_authenticated:
        matched_techniques.append({
            "id": "T1078",
            "name": "Valid Accounts - Compromised Relay / Impersonation",
            "tactic": "Defense Evasion",
            "confidence": "Medium",
            "evidence": "Sender spoofing or unauthenticated routing through unauthorized relay hosts."
        })

    return matched_techniques
