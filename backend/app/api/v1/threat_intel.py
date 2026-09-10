from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.threat_intel import threat_intel_aggregator
from app.api.deps import get_current_user_optional

router = APIRouter()


@router.get("/lookup")
async def lookup_ioc(
    ioc_type: str = Query(..., description="Type of indicator: ip, domain, url, hash"),
    value: str = Query(..., description="Indicator value to investigate"),
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user_optional)
):
    ioc_type = ioc_type.lower().strip()
    val = value.strip()
    
    if ioc_type == "ip":
        result = await threat_intel_aggregator.enrich_ip(val, db=db)
    elif ioc_type == "domain":
        result = await threat_intel_aggregator.enrich_domain(val, db=db)
    elif ioc_type == "url":
        result = await threat_intel_aggregator.enrich_url(val, db=db)
    elif ioc_type in ["hash", "md5", "sha1", "sha256"]:
        result = await threat_intel_aggregator.enrich_hash(val, db=db)
    else:
        return {"error": f"Unsupported IOC type: {ioc_type}. Expected ip, domain, url, or hash"}

    from app.services.audit import log_audit_event
    await log_audit_event(
        db=db,
        action="THREAT_INTEL_LOOKUP",
        target_id=val,
        user_id=_user.id if _user else None,
        details={"ioc_type": ioc_type, "value": val, "is_malicious": result.get("is_malicious", False)}
    )

    return {
        "ioc_type": ioc_type,
        "value": val,
        "enrichment": result
    }
