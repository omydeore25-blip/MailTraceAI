import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from app.schemas.alert import AnalystAlert
from app.schemas.forensic_headers import HeaderForensicReport, ReceivedHop
from app.schemas.authentication import AuthSummary
from app.schemas.ioc import ExtractedIOCs
from app.schemas.risk import RiskScoreResult


def generate_analyst_alerts(
    analysis_id: Optional[str],
    headers_report: Optional[HeaderForensicReport],
    auth_summary: Optional[AuthSummary],
    iocs: Optional[ExtractedIOCs],
    risk_result: Optional[RiskScoreResult],
    ai_insights: Optional[Dict[str, Any]] = None,
    mitre_attack: Optional[List[Dict[str, Any]]] = None,
    hops: Optional[List[ReceivedHop]] = None,
) -> List[AnalystAlert]:
    """
    Generate high-fidelity, evidence-backed analyst alerts based on actual forensic findings.
    
    Adheres to strict rules:
    - Never creates alerts simply because an external API provider is unconfigured.
    - Clean emails produce zero false malicious/critical/high alerts.
    - Every alert contains exact evidence, source component, severity, and related IOC.
    """
    alerts: List[AnalystAlert] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    analysis_ref = analysis_id or "temp-scan"

    # Helper to append alert
    def add_alert(
        severity: str,
        title: str,
        description: str,
        evidence: str,
        source: str,
        related_ioc: Optional[str] = None,
    ):
        alert_id = f"alert-{len(alerts) + 1:03d}-{uuid.uuid4().hex[:6]}"
        alerts.append(
            AnalystAlert(
                id=alert_id,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                source=source,
                related_ioc=related_ioc,
                analysis_id=analysis_ref,
                timestamp=now_iso,
            )
        )

    # 1. Overall Multi-factor Risk Score Alert
    if risk_result:
        score = risk_result.overall_score
        if score >= 75 or risk_result.threat_level == "Critical":
            add_alert(
                severity="Critical",
                title=f"Critical Threat Level Detected (Score: {score:.1f}/100)",
                description="Email exceeds critical security risk threshold with multiple confirmed adversarial indicators.",
                evidence=f"Overall risk score: {score:.1f}. Breakdown: {risk_result.summary}",
                source="Risk Engine",
                related_ioc=None,
            )
        elif score >= 50 or risk_result.threat_level == "Malicious":
            add_alert(
                severity="High",
                title=f"High Risk Score Detected (Score: {score:.1f}/100)",
                description="Email poses significant security risk based on multi-factor heuristic and intelligence evaluation.",
                evidence=f"Risk score: {score:.1f}. Recommended Action: {risk_result.recommended_action}",
                source="Risk Engine",
                related_ioc=None,
            )
        elif score >= 25 or risk_result.threat_level == "Suspicious":
            add_alert(
                severity="Medium",
                title=f"Suspicious Security Characteristics (Score: {score:.1f}/100)",
                description="Email displays anomalous or unverified attributes that warrant analyst inspection.",
                evidence=f"Risk score: {score:.1f}. {risk_result.summary}",
                source="Risk Engine",
                related_ioc=None,
            )

    # 2. AI Linguistic & Intent Classification
    if ai_insights:
        intent = ai_insights.get("intent", {})
        intent_type = intent.get("intent_type", "") if isinstance(intent, dict) else str(intent)
        conf = intent.get("confidence", 0.0) if isinstance(intent, dict) else 0.0
        primary_threat = ai_insights.get("primary_threat") or intent_type

        # Phishing detection
        if "phish" in primary_threat.lower() or "credential" in primary_threat.lower():
            indicators = ai_insights.get("detected_patterns", [])
            add_alert(
                severity="Critical" if conf >= 0.8 else "High",
                title="Credential Phishing Intent Identified",
                description="Natural language analysis detected high-probability credential harvesting or deceptive login redirection.",
                evidence=f"Intent: {primary_threat} (Confidence: {conf * 100:.0f}%). Triggers: {', '.join(indicators[:4]) if indicators else 'Deceptive urgent credential inquiry'}",
                source="AI Linguistic Engine",
                related_ioc=ai_insights.get("suspicious_elements", [None])[0] if ai_insights.get("suspicious_elements") else None,
            )

        # BEC / Wire Fraud detection
        if "bec" in primary_threat.lower() or "wire" in primary_threat.lower() or "financial" in primary_threat.lower() or ai_insights.get("is_bec"):
            patterns = ai_insights.get("financial_indicators", []) or ai_insights.get("detected_patterns", [])
            add_alert(
                severity="Critical",
                title="Business Email Compromise (BEC) / Wire Fraud Indicators",
                description="Linguistic patterns indicate an urgent financial transaction request, payroll redirection, or executive impersonation.",
                evidence=f"Financial keywords/triggers: {', '.join(patterns[:4]) if patterns else 'Wire transfer / bank account alteration request'}",
                source="AI Linguistic Engine",
                related_ioc=headers_report.from_header if headers_report else None,
            )

    # 3. Header Spoofing Indicators
    if headers_report and headers_report.has_spoofed_headers:
        indicators = headers_report.spoofing_indicators or []
        add_alert(
            severity="High",
            title="Email Header Spoofing Detected",
            description="Discrepancy detected between sender display name, envelope From, Return-Path, or Reply-To headers.",
            evidence="; ".join(indicators) if indicators else f"From '{headers_report.from_header}' differs from Reply-To '{headers_report.reply_to}' or Return-Path '{headers_report.return_path}'",
            source="Header Forensics",
            related_ioc=headers_report.from_domain,
        )

    # 4. Email Authentication Failures (SPF, DKIM, DMARC)
    if auth_summary:
        # SPF failure
        spf_status = (auth_summary.spf.status or "").lower()
        if spf_status == "fail":
            add_alert(
                severity="High",
                title="SPF Authentication Failure",
                description="The sending relay IP address is explicitly not authorized to send email on behalf of the From domain.",
                evidence=f"SPF Result: fail. Client IP: {auth_summary.spf.client_ip or 'unknown'}, Evaluated Domain: {auth_summary.spf.evaluated_domain or 'unknown'}. Details: {auth_summary.spf.details or 'SPF record reject'}",
                source="SPF Verifier",
                related_ioc=auth_summary.spf.client_ip or auth_summary.spf.evaluated_domain,
            )
        elif spf_status == "softfail":
            add_alert(
                severity="Medium",
                title="SPF Authentication Softfail",
                description="The sending host is not in the permitted list (~all directive), suggesting unauthorized relaying.",
                evidence=f"SPF Result: softfail. Client IP: {auth_summary.spf.client_ip or 'unknown'}, Domain: {auth_summary.spf.evaluated_domain or 'unknown'}",
                source="SPF Verifier",
                related_ioc=auth_summary.spf.client_ip,
            )

        # DKIM failure
        dkim_status = (auth_summary.dkim.status or "").lower()
        if dkim_status == "fail":
            add_alert(
                severity="High",
                title="DKIM Cryptographic Signature Verification Failed",
                description="Cryptographic signature verification failed or header content was altered during transit.",
                evidence=f"DKIM Status: fail. Selector: {auth_summary.dkim.selector or 'none'}, Domain: {auth_summary.dkim.domain or 'none'}. Details: {auth_summary.dkim.details or 'Signature mismatch'}",
                source="DKIM Verifier",
                related_ioc=auth_summary.dkim.domain,
            )

        # DMARC failure
        dmarc_status = (auth_summary.dmarc.status or "").lower()
        if dmarc_status == "fail":
            add_alert(
                severity="High",
                title="DMARC Policy Failure",
                description="Email failed domain alignment policy checks (SPF and/or DKIM are unaligned with From header).",
                evidence=f"DMARC Status: fail. Policy: {auth_summary.dmarc.policy or 'none'}, SPF Aligned: {auth_summary.dmarc.spf_aligned}, DKIM Aligned: {auth_summary.dmarc.dkim_aligned}. Details: {auth_summary.dmarc.details or 'Alignment failed'}",
                source="DMARC Verifier",
                related_ioc=headers_report.from_domain if headers_report else None,
            )

    # 5. Suspicious / Malicious URLs
    if iocs and iocs.urls:
        for url in iocs.urls:
            if url.is_malicious:
                add_alert(
                    severity="Critical",
                    title=f"Malicious URL Identified: {url.defanged_value[:40]}",
                    description="URL has been flagged as malicious by verified threat intelligence feeds.",
                    evidence=f"URL: {url.defanged_value}. Reputation Score: {url.reputation_score:.0f}/100. Provider data: {str(url.enrichment.get('virustotal', {}).get('positives', 'Confirmed Malicious'))}",
                    source="Threat Intelligence",
                    related_ioc=url.value,
                )
            elif url.reputation_score >= 35 or "login" in url.value.lower() or "verify" in url.value.lower() or "update" in url.value.lower():
                # Only flag if there are actually suspicious indicators or score
                if url.reputation_score >= 35:
                    add_alert(
                        severity="Medium",
                        title=f"Suspicious URL Detected: {url.defanged_value[:40]}",
                        description="URL exhibits suspicious reputation scores or deceptive URL structure.",
                        evidence=f"URL: {url.defanged_value}. Reputation Score: {url.reputation_score:.0f}/100",
                        source="IOC Extractor",
                        related_ioc=url.value,
                    )

    # 6. Malicious / Suspicious Attachments & Hashes
    if iocs and iocs.attachments:
        for att in iocs.attachments:
            if att.risk_level == "Critical":
                add_alert(
                    severity="Critical",
                    title=f"Malicious Attachment Detected: {att.filename}",
                    description="Attachment is confirmed malware or contains high-risk executable payload.",
                    evidence=f"File: {att.filename} (SHA256: {att.sha256[:16]}...). Risk flags: {', '.join(att.risk_flags)}",
                    source="Attachment Inspector",
                    related_ioc=att.sha256,
                )
            elif att.risk_level == "High" or att.is_executable_or_script or att.is_macro_enabled:
                add_alert(
                    severity="High",
                    title=f"Suspicious Attachment Architecture: {att.filename}",
                    description="File contains executable code, scripts, or embedded macro routines often used in initial access droppers.",
                    evidence=f"File: {att.filename}, Content-Type: {att.content_type}. Executable: {att.is_executable_or_script}, Macro: {att.is_macro_enabled}. Flags: {', '.join(att.risk_flags)}",
                    source="Attachment Inspector",
                    related_ioc=att.sha256,
                )

    # 7. Relay IP Abuse Reputation & Anomalous Hops
    if hops:
        for hop in hops:
            if hop.anomalous:
                add_alert(
                    severity="Medium",
                    title=f"Anomalous Relay Transit Hop #{hop.hop_number}",
                    description=hop.anomaly_reason or "Clock skew, forged MTA timestamp, or excessive relay latency detected.",
                    evidence=f"Hop #{hop.hop_number} (IP: {hop.ip or 'unknown'}). Delay: {hop.delay_seconds}s. Anomaly: {hop.anomaly_reason}",
                    source="Hop Analyzer",
                    related_ioc=hop.ip,
                )
            # GeoLocation query lookup failure (excluding unconfigured key)
            if hop.geo_status == "error" and hop.geo_error:
                add_alert(
                    severity="Low",
                    title=f"GeoLocation Lookup Error for Hop #{hop.hop_number}",
                    description="An active network lookup error occurred while resolving geographic coordinates for this public IP.",
                    evidence=f"IP: {hop.ip}. Error: {hop.geo_error}",
                    source="IPinfo Client",
                    related_ioc=hop.ip,
                )

    if iocs and iocs.ips:
        for ip_item in iocs.ips:
            if ip_item.is_malicious or ip_item.reputation_score >= 40:
                add_alert(
                    severity="High",
                    title=f"Public IP with High Abuse Reputation: {ip_item.defanged_value}",
                    description="Extracted transit or hosting IP address is associated with malicious activity in threat reputation databases.",
                    evidence=f"IP: {ip_item.defanged_value}. Reputation Score: {ip_item.reputation_score:.0f}/100",
                    source="Threat Intelligence",
                    related_ioc=ip_item.value,
                )

    # 8. MITRE ATT&CK Techniques Mapped
    if mitre_attack:
        for tech in mitre_attack:
            tech_id = tech.get("id", "ATT&CK")
            name = tech.get("name", "Unknown Technique")
            confidence = tech.get("confidence", "Medium")
            evidence_str = tech.get("evidence", "Observable forensic pattern")

            # Mapped MITRE techniques
            severity = "High" if confidence == "High" else "Medium"
            add_alert(
                severity=severity,
                title=f"MITRE ATT&CK: {tech_id} - {name}",
                description=f"Observable forensic artifacts correlate with MITRE ATT&CK tactic '{tech.get('tactic', 'Initial Access')}'.",
                evidence=evidence_str,
                source="MITRE Mapper",
                related_ioc=tech_id,
            )

    return alerts
