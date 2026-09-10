import io
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.email_analysis import EmailAnalysis
from app.models.ioc import IOC
from app.schemas.email_analysis import EmailAnalysisOverview, EmailAnalysisDetail, EmailAnalysisCreateRequest
from app.schemas.forensic_headers import HeaderForensicReport, ReceivedHop
from app.schemas.authentication import AuthSummary, SPFResult, DKIMResult, DMARCResult, ARCResult
from app.schemas.ioc import ExtractedIOCs, AttachmentMeta, IOCItem
from app.schemas.risk import RiskScoreResult

from app.services.email_parser import parse_raw_eml, parse_raw_msg, analyze_headers, parse_received_hops
from app.services.authentication import audit_authentication
from app.services.ioc_extractor import extract_all_iocs
from app.services.threat_intel import threat_intel_aggregator
from app.services.ai_detector import classify_email_intent, compute_risk_score
from app.services.attribution import map_mitre_attack_techniques, correlate_campaign_and_actor
from app.services.alerts import generate_analyst_alerts
from app.services.graph import graph_service
from app.core.config import settings
from app.api.deps import get_current_user_optional

router = APIRouter()


async def execute_forensic_pipeline(
    content: bytes,
    filename: str = "uploaded_email.eml",
    db: Optional[AsyncSession] = None
) -> EmailAnalysisDetail:
    """Execute end-to-end deterministic forensic analysis pipeline on raw email bytes."""
    
    # 1. Parsing
    if filename.lower().endswith(".msg"):
        parsed = parse_raw_msg(content)
    else:
        parsed = parse_raw_eml(content)

    # 2. Hop Timeline Analysis
    raw_hops = parsed.get("received_headers", [])
    hops: List[ReceivedHop] = parse_received_hops(raw_hops)

    # Enrich hop IPs with GeoIP
    for hop in hops:
        if hop.ip:
            geo = await threat_intel_aggregator.ipinfo.check_ip(hop.ip)
            if geo:
                hop.country = geo.get("country")
                hop.region = geo.get("region")
                hop.city = geo.get("city")
                hop.latitude = geo.get("latitude")
                hop.longitude = geo.get("longitude")
                hop.asn = geo.get("asn") or geo.get("org")
                hop.org = geo.get("org")
                hop.isp = geo.get("isp") or geo.get("org")
                hop.is_private = geo.get("is_private", False)
                hop.geo_status = geo.get("geo_status")
                hop.geo_error = geo.get("error_message")

    # 3. Header Forensics
    headers_report, spoof_flags = analyze_headers(parsed, hops)

    # Origin IP for SPF check
    origin_ip = hops[0].ip if hops and hops[0].ip else None

    # 4. Authentication Audit
    auth_summary: AuthSummary = audit_authentication(
        from_domain=parsed.get("from_domain", ""),
        client_ip=origin_ip,
        raw_headers=parsed.get("raw_headers", ""),
        raw_message_bytes=content
    )

    # 5. Extract IOCs
    hop_ips = [h.ip for h in hops if h.ip]
    iocs: ExtractedIOCs = extract_all_iocs(parsed, hop_ips=hop_ips)

    # 6. Enrich Extracted IOCs via Threat Intelligence
    for url_item in iocs.urls:
        ti = await threat_intel_aggregator.enrich_url(url_item.value, db=db)
        if ti:
            url_item.reputation_score = ti.get("reputation_score", url_item.reputation_score)
            url_item.is_malicious = ti.get("is_malicious", url_item.is_malicious)
            url_item.enrichment = ti

    for dom_item in iocs.domains:
        ti = await threat_intel_aggregator.enrich_domain(dom_item.value, db=db)
        if ti:
            dom_item.reputation_score = max(dom_item.reputation_score, ti.get("reputation_score", 0.0))
            dom_item.is_malicious = dom_item.is_malicious or ti.get("is_malicious", False)
            dom_item.enrichment.update(ti)

    for ip_item in iocs.ips:
        ti = await threat_intel_aggregator.enrich_ip(ip_item.value, db=db)
        if ti:
            ip_item.reputation_score = ti.get("reputation_score", ip_item.reputation_score)
            ip_item.is_malicious = ti.get("is_malicious", ip_item.is_malicious)
            ip_item.enrichment = ti

    for att_item in iocs.attachments:
        ti = await threat_intel_aggregator.enrich_hash(att_item.sha256, db=db)
        if ti and ti.get("is_malicious"):
            att_item.risk_level = "Critical"
            att_item.risk_flags.append(f"Threat Intelligence Flag: {ti.get('threat_name', 'Known Malicious')}")

    # 7. AI & Linguistic Intent Analysis
    has_mal_att = any(a.risk_level in ["High", "Critical"] for a in iocs.attachments)
    has_mal_url = any(u.is_malicious for u in iocs.urls)
    ai_intent = classify_email_intent(
        subject=parsed.get("subject", ""),
        plain_body=parsed.get("body_plain", ""),
        html_body=parsed.get("body_html", ""),
        has_malicious_attachment=has_mal_att,
        has_malicious_url=has_mal_url,
        is_spoofed=headers_report.has_spoofed_headers
    )

    # 8. Multi-factor Risk Score
    risk_result: RiskScoreResult = compute_risk_score(
        headers_report=headers_report,
        auth_summary=auth_summary,
        iocs=iocs,
        ai_intent=ai_intent
    )

    # 9. MITRE ATT&CK Threat Mapping
    mitre_attack = map_mitre_attack_techniques(
        headers_report=headers_report,
        auth_summary=auth_summary,
        iocs=iocs,
        ai_intent=ai_intent
    )

    # 10. Campaign Correlation & Attribution
    attr = await correlate_campaign_and_actor(
        headers_report=headers_report,
        auth_summary=auth_summary,
        iocs=iocs,
        ai_intent=ai_intent,
        db=db
    )

    # 11. Build Response & Persist to Database if session provided
    record_id = None
    if db:
        new_analysis = EmailAnalysis(
            message_id=parsed.get("message_id"),
            subject=parsed.get("subject"),
            sender=parsed.get("from_address") or "unknown@sender",
            from_name=parsed.get("from_name"),
            reply_to=parsed.get("reply_to"),
            return_path=parsed.get("return_path"),
            recipients=parsed.get("to", []),
            email_date=parsed.get("date"),
            raw_headers=parsed.get("raw_headers"),
            body_plain=parsed.get("body_plain"),
            body_html=parsed.get("body_html"),
            risk_score=risk_result.overall_score,
            threat_level=risk_result.threat_level,
            risk_breakdown=risk_result.model_dump(),
            auth_results=auth_summary.model_dump(),
            hop_timeline=[h.model_dump() for h in hops],
            attachments_meta=[a.model_dump() for a in iocs.attachments],
            ai_insights=ai_intent,
            mitre_attack=mitre_attack,
            campaign_id=attr.get("campaign_id"),
            threat_actor=attr.get("threat_actor")
        )
        db.add(new_analysis)
        await db.flush() # obtain ID
        record_id = new_analysis.id

        # Add IOC rows
        all_iocs = []
        for u in iocs.urls:
            all_iocs.append(IOC(analysis_id=record_id, ioc_type="url", value=u.value, defanged_value=u.defanged_value, reputation_score=u.reputation_score, is_malicious=u.is_malicious, enrichment_data=u.enrichment))
        for d in iocs.domains:
            all_iocs.append(IOC(analysis_id=record_id, ioc_type="domain", value=d.value, defanged_value=d.defanged_value, reputation_score=d.reputation_score, is_malicious=d.is_malicious, enrichment_data=d.enrichment))
        for i in iocs.ips:
            all_iocs.append(IOC(analysis_id=record_id, ioc_type="ip", value=i.value, defanged_value=i.defanged_value, reputation_score=i.reputation_score, is_malicious=i.is_malicious, enrichment_data=i.enrichment))
        for a in iocs.attachments:
            all_iocs.append(IOC(analysis_id=record_id, ioc_type="sha256", value=a.sha256, defanged_value=a.sha256, reputation_score=100.0 if a.risk_level in ["High", "Critical"] else 0.0, is_malicious=a.risk_level in ["High", "Critical"], enrichment_data={"filename": a.filename, "flags": a.risk_flags}))
        
        db.add_all(all_iocs)
        await db.commit()
        await db.refresh(new_analysis)

        from app.services.audit import log_audit_event
        await log_audit_event(
            db=db,
            action="ANALYSIS_COMPLETED",
            target_id=record_id,
            details={
                "subject": parsed.get("subject"),
                "sender": parsed.get("from_address"),
                "risk_score": risk_result.overall_score,
                "threat_level": risk_result.threat_level,
                "campaign_id": attr.get("campaign_id")
            }
        )

    # 11. Generate Real-Time Evidence-Backed Analyst Alerts
    alerts = generate_analyst_alerts(
        analysis_id=record_id or "temp-id",
        headers_report=headers_report,
        auth_summary=auth_summary,
        iocs=iocs,
        risk_result=risk_result,
        ai_insights=ai_intent,
        mitre_attack=mitre_attack,
        hops=hops,
    )

    # 12. Build Threat / Infrastructure Graph
    graph_dict = {
        "id": record_id or "temp-id",
        "subject": parsed.get("subject"),
        "sender": parsed.get("from_address") or "unknown@sender",
        "recipients": parsed.get("to", []),
        "risk_score": risk_result.overall_score,
        "threat_level": risk_result.threat_level,
        "hops": [h.model_dump() for h in hops],
        "iocs": [
            {"ioc_type": "url", "value": u.value, "defanged_value": u.defanged_value, "reputation_score": u.reputation_score, "is_malicious": u.is_malicious}
            for u in iocs.urls
        ] + [
            {"ioc_type": "domain", "value": d.value, "defanged_value": d.defanged_value, "reputation_score": d.reputation_score, "is_malicious": d.is_malicious}
            for d in iocs.domains
        ] + [
            {"ioc_type": "ip", "value": i.value, "defanged_value": i.defanged_value, "reputation_score": i.reputation_score, "is_malicious": i.is_malicious}
            for i in iocs.ips
        ],
        "attachments": [a.model_dump() for a in iocs.attachments],
        "mitre_attack": mitre_attack,
        "threat_actor": attr.get("threat_actor"),
        "campaign_id": attr.get("campaign_id"),
    }
    graph_data = await graph_service.get_graph_for_analysis(graph_dict)

    return EmailAnalysisDetail(
        id=record_id or "temp-id",
        message_id=parsed.get("message_id"),
        subject=parsed.get("subject"),
        sender=parsed.get("from_address") or "unknown@sender",
        from_name=parsed.get("from_name"),
        reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"),
        recipients=parsed.get("to", []),
        email_date=parsed.get("date"),
        body_plain=parsed.get("body_plain"),
        body_html=parsed.get("body_html"),
        raw_headers=parsed.get("raw_headers"),
        risk_score=risk_result.overall_score,
        threat_level=risk_result.threat_level,
        campaign_id=attr.get("campaign_id"),
        threat_actor=attr.get("threat_actor"),
        created_at=datetime.now(timezone.utc),
        headers_report=headers_report,
        auth_summary=auth_summary,
        extracted_iocs=iocs,
        risk_assessment=risk_result,
        ai_insights=ai_intent,
        mitre_attack=mitre_attack,
        hops=hops,
        attachments=iocs.attachments,
        alerts=alerts,
        graph=graph_data,
    )


@router.post("/upload", response_model=EmailAnalysisDetail)
async def upload_email_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    filename = file.filename or "uploaded_email.eml"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in [".eml", ".msg", ".txt"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Only .eml, .msg, and .txt files are accepted for forensic inspection."
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty email file uploaded")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB"
        )
    
    return await execute_forensic_pipeline(content, filename=filename, db=db)


@router.post("/paste", response_model=EmailAnalysisDetail)
async def analyze_pasted_email(
    request: EmailAnalysisCreateRequest,
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    if not request.raw_email_text:
        raise HTTPException(status_code=400, detail="No email content provided")
    
    content = request.raw_email_text.encode("utf-8")
    return await execute_forensic_pipeline(content, filename="pasted.eml", db=db)


@router.get("/", response_model=List[EmailAnalysisOverview])
async def list_recent_analyses(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    result = await db.execute(
        select(EmailAnalysis)
        .order_by(desc(EmailAnalysis.created_at))
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


@router.get("/{analysis_id}", response_model=EmailAnalysisDetail)
async def get_analysis_by_id(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    result = await db.execute(
        select(EmailAnalysis)
        .options(selectinload(EmailAnalysis.iocs))
        .where(EmailAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Email analysis record not found")

    # Reconstitute schemas from JSON fields
    hops = [ReceivedHop(**h) for h in analysis.hop_timeline]
    auth_summary = AuthSummary(**analysis.auth_results) if analysis.auth_results else None
    risk_assessment = RiskScoreResult(**analysis.risk_breakdown) if analysis.risk_breakdown else None
    
    urls = [IOCItem(ioc_type="url", value=i.value, defanged_value=i.defanged_value or i.value, reputation_score=i.reputation_score, is_malicious=i.is_malicious, enrichment=i.enrichment_data) for i in analysis.iocs if i.ioc_type == "url"]
    ips = [IOCItem(ioc_type="ip", value=i.value, defanged_value=i.defanged_value or i.value, reputation_score=i.reputation_score, is_malicious=i.is_malicious, enrichment=i.enrichment_data) for i in analysis.iocs if i.ioc_type == "ip"]
    domains = [IOCItem(ioc_type="domain", value=i.value, defanged_value=i.defanged_value or i.value, reputation_score=i.reputation_score, is_malicious=i.is_malicious, enrichment=i.enrichment_data) for i in analysis.iocs if i.ioc_type == "domain"]
    attachments = [AttachmentMeta(**a) for a in analysis.attachments_meta]

    extracted_iocs = ExtractedIOCs(
        urls=urls,
        ips=ips,
        domains=domains,
        attachments=attachments,
        total_iocs_found=len(analysis.iocs),
        malicious_iocs_count=sum(1 for i in analysis.iocs if i.is_malicious)
    )

    headers_report = HeaderForensicReport(
        subject=analysis.subject,
        message_id=analysis.message_id,
        date=analysis.email_date,
        from_header=analysis.sender,
        from_name=analysis.from_name,
        from_domain=analysis.sender.split("@")[-1] if "@" in analysis.sender else "",
        reply_to=analysis.reply_to,
        return_path=analysis.return_path,
        to=analysis.recipients,
        cc=[],
        hops=hops,
        spoofing_indicators=analysis.risk_breakdown.get("factors", [{}])[0].get("flagged_items", []),
        has_spoofed_headers=analysis.risk_breakdown.get("factors", [{}])[0].get("score", 0.0) > 0,
        total_transit_time_seconds=sum(h.delay_seconds or 0 for h in hops)
    )

    alerts = generate_analyst_alerts(
        analysis_id=analysis.id,
        headers_report=headers_report,
        auth_summary=auth_summary,
        iocs=extracted_iocs,
        risk_result=risk_assessment,
        ai_insights=analysis.ai_insights or {},
        mitre_attack=analysis.mitre_attack or [],
        hops=hops,
    )

    graph_dict = {
        "id": analysis.id,
        "subject": analysis.subject,
        "sender": analysis.sender,
        "recipients": analysis.recipients or [],
        "risk_score": analysis.risk_score,
        "threat_level": analysis.threat_level,
        "hops": [h.model_dump() for h in hops],
        "iocs": [
            {"ioc_type": "url", "value": u.value, "defanged_value": u.defanged_value, "reputation_score": u.reputation_score, "is_malicious": u.is_malicious}
            for u in extracted_iocs.urls
        ] + [
            {"ioc_type": "domain", "value": d.value, "defanged_value": d.defanged_value, "reputation_score": d.reputation_score, "is_malicious": d.is_malicious}
            for d in extracted_iocs.domains
        ] + [
            {"ioc_type": "ip", "value": i.value, "defanged_value": i.defanged_value, "reputation_score": i.reputation_score, "is_malicious": i.is_malicious}
            for i in extracted_iocs.ips
        ],
        "attachments": [a.model_dump() for a in attachments],
        "mitre_attack": analysis.mitre_attack or [],
        "threat_actor": analysis.threat_actor,
        "campaign_id": analysis.campaign_id,
    }
    graph_data = await graph_service.get_graph_for_analysis(graph_dict)

    return EmailAnalysisDetail(
        id=analysis.id,
        message_id=analysis.message_id,
        subject=analysis.subject,
        sender=analysis.sender,
        from_name=analysis.from_name,
        reply_to=analysis.reply_to,
        return_path=analysis.return_path,
        recipients=analysis.recipients,
        email_date=analysis.email_date,
        body_plain=analysis.body_plain,
        body_html=analysis.body_html,
        raw_headers=analysis.raw_headers,
        risk_score=analysis.risk_score,
        threat_level=analysis.threat_level,
        campaign_id=analysis.campaign_id,
        threat_actor=analysis.threat_actor,
        created_at=analysis.created_at,
        headers_report=headers_report,
        auth_summary=auth_summary,
        extracted_iocs=extracted_iocs,
        risk_assessment=risk_assessment,
        ai_insights=analysis.ai_insights,
        mitre_attack=analysis.mitre_attack,
        hops=hops,
        attachments=attachments,
        alerts=alerts,
        graph=graph_data,
    )


@router.delete("/{analysis_id}", status_code=status.HTTP_200_OK)
async def delete_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    result = await db.execute(select(EmailAnalysis).where(EmailAnalysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Email analysis record not found")
    
    from app.services.audit import log_audit_event
    await log_audit_event(
        db=db,
        action="CASE_DELETED",
        target_id=analysis_id,
        user_id=_user.id if _user else None,
        details={"case_id": analysis_id, "subject": analysis.subject}
    )

    await db.delete(analysis)
    await db.commit()
    return {"status": "deleted", "id": analysis_id}

