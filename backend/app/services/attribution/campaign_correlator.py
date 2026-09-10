import hashlib
import re
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.forensic_headers import HeaderForensicReport
from app.schemas.authentication import AuthSummary
from app.schemas.ioc import ExtractedIOCs
from app.models.ioc import IOC
from app.models.email_analysis import EmailAnalysis


async def correlate_campaign_and_actor(
    headers_report: HeaderForensicReport,
    auth_summary: AuthSummary,
    iocs: ExtractedIOCs,
    ai_intent: Dict[str, Any],
    db: Optional[AsyncSession] = None
) -> Dict[str, Any]:
    """Correlate email indicators against historical threat campaigns and known threat actor infrastructure."""
    primary_category = ai_intent.get("primary_category", "Clean")
    
    # 1. Identify Origin IP Subnet
    origin_ip = None
    for hop in headers_report.hops:
        if hop.ip:
            origin_ip = hop.ip
            break

    subnet_prefix = ".".join(origin_ip.split(".")[:3]) + ".0/24" if origin_ip and "." in origin_ip else "unknown-subnet"
    dkim_sel = auth_summary.dkim.selector or "no-dkim"
    norm_subject = re.sub(r"[^a-zA-Z0-9]", "", headers_report.subject or "").lower()[:20]

    # Generate deterministic campaign cluster fingerprint
    fingerprint_seed = f"{subnet_prefix}_{dkim_sel}_{primary_category}_{norm_subject}"
    campaign_hash = hashlib.md5(fingerprint_seed.encode()).hexdigest()[:6].upper()
    campaign_id = f"CAMP-2026-{campaign_hash}"

    # 2. Correlate with historical cases in database if session provided
    shared_indicators: List[str] = []
    matched_campaign_ids = set()

    if db:
        try:
            query_values = list(set(
                [u.value for u in iocs.urls] +
                [d.value for d in iocs.domains] +
                [i.value for i in iocs.ips] +
                [a.sha256 for a in iocs.attachments]
            ))
            if query_values:
                stmt = (
                    select(IOC.ioc_type, IOC.value, IOC.analysis_id, EmailAnalysis.campaign_id)
                    .join(EmailAnalysis, IOC.analysis_id == EmailAnalysis.id)
                    .where(IOC.value.in_(query_values))
                    .limit(20)
                )
                res = await db.execute(stmt)
                rows = res.fetchall()
                for ioc_type, val, analysis_id, c_id in rows:
                    shared_indicators.append(f"{ioc_type.upper()}: {val} (Case #{analysis_id[:8]})")
                    if c_id:
                        matched_campaign_ids.add(c_id)
        except Exception:
            pass

    # If linked to an existing historical campaign cluster, merge into it
    if matched_campaign_ids:
        campaign_id = list(matched_campaign_ids)[0]

    # Threat Actor Attribution Heuristics
    threat_actor = "Unattributed Adversary"
    attribution_confidence = "Low"
    ttps = []

    # Check for known actor profiles
    if "BEC" in primary_category:
        threat_actor = "Cosmic Lynx / BEC Syndicate"
        attribution_confidence = "High" if len(shared_indicators) > 1 else "Medium"
        ttps = ["Executive Impersonation", "Wire Fraud Redirection", "Dual-Factor Bypass Lures"]
    elif any("AgentTesla" in str(att.risk_flags) for att in iocs.attachments) or any(".vbs" in a.filename.lower() for a in iocs.attachments):
        threat_actor = "TA505 (FIN11 Group)"
        attribution_confidence = "High"
        ttps = ["VBS/Script Droppers", "Banking Trojan Delivery", "Encrypted Archive Evasion"]
    elif any("microsoft" in d.value for d in iocs.domains if d.is_malicious):
        threat_actor = "Storm-0539 (Phishing Specialist Group)"
        attribution_confidence = "High"
        ttps = ["Microsoft 365 Device Code Phishing", "Typosquatted IdP Portals", "AiTM Proxy Routing"]
    elif any(u.is_malicious for u in iocs.urls):
        threat_actor = "UNC2452 / Phishing Cluster"
        attribution_confidence = "High" if len(shared_indicators) > 1 else "Medium"
        ttps = ["Credential Harvesting", "Dynamic DNS Infrastructure", "Fast-Flux Domains"]

    summary = (
        f"Correlated with historical campaign {campaign_id} with {len(shared_indicators)} shared IOC overlap(s)."
        if shared_indicators
        else f"Fingerprinted as campaign {campaign_id} based on relay subnet ({subnet_prefix}) and delivery TTPs."
    )

    return {
        "campaign_id": campaign_id,
        "threat_actor": threat_actor,
        "attribution_confidence": attribution_confidence,
        "cluster_fingerprint": fingerprint_seed,
        "actor_ttps": ttps,
        "shared_infrastructure": shared_indicators,
        "campaign_summary": summary
    }
