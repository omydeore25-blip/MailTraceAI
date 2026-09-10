from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.email_analysis import EmailAnalysis
from app.services.graph import graph_service
from app.schemas.graph import GraphData
from app.api.deps import get_current_user_optional

router = APIRouter()


@router.get("/analysis/{analysis_id}", response_model=GraphData)
async def get_analysis_graph(
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
        raise HTTPException(status_code=404, detail="Email analysis not found")

    analysis_data = {
        "id": analysis.id,
        "subject": analysis.subject,
        "sender": analysis.sender,
        "recipients": analysis.recipients or [],
        "risk_score": analysis.risk_score,
        "threat_level": analysis.threat_level,
        "hops": analysis.hop_timeline or [],
        "attachments": analysis.attachments_meta or [],
        "mitre_attack": analysis.mitre_attack or [],
        "threat_actor": analysis.threat_actor,
        "campaign_id": analysis.campaign_id,
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

    graph = await graph_service.get_graph_for_analysis(analysis_data)
    return graph
