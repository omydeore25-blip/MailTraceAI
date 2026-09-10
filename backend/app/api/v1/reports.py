import io
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.email_analysis import EmailAnalysis
from app.services.reporting import generate_forensic_pdf, export_forensic_json
from app.api.deps import get_current_user_optional

router = APIRouter()


@router.get("/{analysis_id}/pdf")
async def download_pdf_report(
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
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis_dict = {
        "id": analysis.id,
        "subject": analysis.subject,
        "sender": analysis.sender,
        "recipients": analysis.recipients,
        "risk_score": analysis.risk_score,
        "threat_level": analysis.threat_level,
        "auth_results": analysis.auth_results,
        "hop_timeline": analysis.hop_timeline,
        "mitre_attack": analysis.mitre_attack,
        "campaign_id": analysis.campaign_id,
        "threat_actor": analysis.threat_actor,
        "iocs": [
            {
                "ioc_type": i.ioc_type,
                "value": i.value,
                "defanged_value": i.defanged_value,
                "reputation_score": i.reputation_score,
                "is_malicious": i.is_malicious
            }
            for i in analysis.iocs
        ]
    }

    pdf_bytes = generate_forensic_pdf(analysis_dict)
    filename = f"MailTrace_Report_{analysis.id[:8]}.pdf"
    
    from app.services.audit import log_audit_event
    await log_audit_event(
        db=db,
        action="REPORT_GENERATED",
        target_id=analysis.id,
        user_id=_user.id if _user else None,
        details={"format": "pdf", "filename": filename}
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/{analysis_id}/json")
async def download_json_report(
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
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis_dict = {
        "case_id": analysis.id,
        "message_id": analysis.message_id,
        "subject": analysis.subject,
        "sender": analysis.sender,
        "recipients": analysis.recipients,
        "date": analysis.email_date,
        "risk_score": analysis.risk_score,
        "threat_level": analysis.threat_level,
        "auth_results": analysis.auth_results,
        "hops": analysis.hop_timeline,
        "ai_insights": analysis.ai_insights,
        "mitre_attack": analysis.mitre_attack,
        "campaign_id": analysis.campaign_id,
        "threat_actor": analysis.threat_actor,
        "iocs": [
            {
                "type": i.ioc_type,
                "value": i.value,
                "defanged": i.defanged_value,
                "score": i.reputation_score,
                "malicious": i.is_malicious,
                "enrichment": i.enrichment_data
            }
            for i in analysis.iocs
        ]
    }

    json_data = export_forensic_json(analysis_dict)
    filename = f"MailTrace_Case_{analysis.id[:8]}.json"

    from app.services.audit import log_audit_event
    await log_audit_event(
        db=db,
        action="REPORT_GENERATED",
        target_id=analysis.id,
        user_id=_user.id if _user else None,
        details={"format": "json", "filename": filename}
    )

    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
