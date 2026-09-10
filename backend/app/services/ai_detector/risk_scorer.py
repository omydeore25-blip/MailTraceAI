from typing import Dict, Any, List
from app.schemas.risk import RiskScoreResult, RiskFactor
from app.schemas.forensic_headers import HeaderForensicReport
from app.schemas.authentication import AuthSummary
from app.schemas.ioc import ExtractedIOCs


def compute_risk_score(
    headers_report: HeaderForensicReport,
    auth_summary: AuthSummary,
    iocs: ExtractedIOCs,
    ai_intent: Dict[str, Any]
) -> RiskScoreResult:
    """
    Calculate an explainable multi-factor risk score (0 to 100).
    Weights:
      - Header Forensics: 25%
      - Protocol Authentication: 20%
      - Threat Intelligence (IOCs): 25%
      - AI / Social Engineering: 20%
      - Attachment Payloads: 10%
    """
    # 1. Header Forensics (Weight: 25)
    header_flags = list(headers_report.spoofing_indicators)
    anomalous_hops = [h for h in headers_report.hops if h.anomalous]
    for h in anomalous_hops:
        header_flags.append(f"Hop #{h.hop_number}: {h.anomaly_reason}")

    header_score = 0.0
    if headers_report.has_spoofed_headers:
        header_score += 60.0
    if anomalous_hops:
        header_score += 30.0
    header_score = min(100.0, header_score + (len(header_flags) * 15.0))
    weighted_header = (header_score * 0.25)

    # 2. Authentication Protocol (Weight: 20)
    auth_flags = list(auth_summary.failure_reasons)
    auth_score = 0.0
    if auth_summary.dmarc.status == "fail":
        auth_score += 70.0
    elif auth_summary.spf.status in ["fail", "softfail", "permerror"]:
        auth_score += 40.0
    if auth_summary.dkim.status in ["fail", "invalid"]:
        auth_score += 40.0
    auth_score = min(100.0, auth_score)
    weighted_auth = (auth_score * 0.20)

    # 3. Threat Intelligence IOCs (Weight: 25)
    ti_flags = []
    max_ioc_reputation = 0.0
    for u in iocs.urls:
        if u.is_malicious or u.reputation_score > 50:
            ti_flags.append(f"Malicious URL detected: {u.defanged_value}")
            max_ioc_reputation = max(max_ioc_reputation, u.reputation_score)
    for d in iocs.domains:
        if d.is_malicious or d.reputation_score > 50:
            ti_flags.append(f"Suspicious / Typosquatted Domain: {d.defanged_value}")
            max_ioc_reputation = max(max_ioc_reputation, d.reputation_score)
    for ip in iocs.ips:
        if ip.is_malicious or ip.reputation_score > 50:
            ti_flags.append(f"Reported Malicious IP: {ip.defanged_value}")
            max_ioc_reputation = max(max_ioc_reputation, ip.reputation_score)

    ti_score = min(100.0, max_ioc_reputation + (len(ti_flags) * 10.0))
    weighted_ti = (ti_score * 0.25)

    # 4. AI & Linguistic Intent (Weight: 20)
    ai_heuristics = ai_intent.get("linguistic_heuristics", {})
    ai_score = float(ai_heuristics.get("heuristic_score", 0.0))
    ai_flags = list(ai_heuristics.get("triggered_patterns", []))
    weighted_ai = (ai_score * 0.20)

    # 5. Attachment Payloads (Weight: 10)
    att_flags = []
    att_score = 0.0
    for att in iocs.attachments:
        if att.risk_level == "Critical":
            att_score = max(att_score, 100.0)
            att_flags.append(f"High-Risk Executable: {att.filename}")
        elif att.risk_level == "High":
            att_score = max(att_score, 75.0)
            att_flags.append(f"Macro / Weaponized Container: {att.filename}")
        elif att.risk_level == "Medium":
            att_score = max(att_score, 40.0)
            att_flags.append(f"Archive / Compressed Payload: {att.filename}")
    att_score = min(100.0, att_score)
    weighted_att = (att_score * 0.10)

    # Overall Composite Score
    overall_score = round(weighted_header + weighted_auth + weighted_ti + weighted_ai + weighted_att, 1)

    # Threat Level Classification
    if overall_score >= 80.0:
        threat_level = "Critical"
        recommended_action = "Block Sender, Isolate Recipient Mailbox & Execute Incident Response Triage"
        summary = "Critical threat detected. Message exhibits weaponized payload or high-confidence credential harvesting intent."
    elif overall_score >= 60.0:
        threat_level = "Malicious"
        recommended_action = "Quarantine Email & Blacklist Source Relaying IP"
        summary = "Malicious communication identified. Fails multiple authentication protocols with suspicious IOC indicators."
    elif overall_score >= 30.0:
        threat_level = "Suspicious"
        recommended_action = "Deliver with Forensic Warning Banner & Sanitize Links"
        summary = "Suspicious anomalies observed in headers or language cues requiring analyst caution."
    else:
        threat_level = "Clean"
        recommended_action = "Deliver to Recipient Inbox"
        summary = "Email passed all forensic verification checks and threat intelligence lookups."

    factors = [
        RiskFactor(
            category="Header Forensics",
            weight_percentage=25,
            score=header_score,
            weighted_contribution=round(weighted_header, 1),
            description="Inspection of display name spoofing, sender mismatches, and transit latency.",
            flagged_items=header_flags
        ),
        RiskFactor(
            category="Protocol Authentication",
            weight_percentage=20,
            score=auth_score,
            weighted_contribution=round(weighted_auth, 1),
            description="Cryptographic and DNS policy evaluation across SPF, DKIM, DMARC, and ARC.",
            flagged_items=auth_flags
        ),
        RiskFactor(
            category="Threat Intelligence",
            weight_percentage=25,
            score=ti_score,
            weighted_contribution=round(weighted_ti, 1),
            description="Global reputation analysis of extracted IPs, domains, and URLs.",
            flagged_items=ti_flags
        ),
        RiskFactor(
            category="AI Intent & Heuristics",
            weight_percentage=20,
            score=ai_score,
            weighted_contribution=round(weighted_ai, 1),
            description="NLP and pattern evaluation for social engineering, urgency, and financial deception.",
            flagged_items=ai_flags
        ),
        RiskFactor(
            category="Payload & Attachments",
            weight_percentage=10,
            score=att_score,
            weighted_contribution=round(weighted_att, 1),
            description="Analysis of file extensions, macro signatures, and binary hashes.",
            flagged_items=att_flags
        )
    ]

    return RiskScoreResult(
        overall_score=overall_score,
        threat_level=threat_level,
        summary=summary,
        factors=factors,
        recommended_action=recommended_action
    )
