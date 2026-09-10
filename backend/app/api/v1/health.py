from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db
from app.db.neo4j_session import is_neo4j_available
from app.core.config import settings

router = APIRouter()


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    # Check SQL DB
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
        
    # Check Neo4j
    neo4j_ok = await is_neo4j_available()
    
    return {
        "status": "healthy" if db_ok else "degraded",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": {
            "status": "connected" if db_ok else "disconnected",
            "type": "sqlite" if settings.DATABASE_URL.startswith("sqlite") else "postgresql"
        },
        "graph_engine": {
            "neo4j_available": neo4j_ok,
            "mode": "neo4j_native" if neo4j_ok else "postgres_cte_fallback"
        },
        "threat_intel": {
            "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
            "abuseipdb_configured": bool(settings.ABUSEIPDB_API_KEY),
            "ipinfo_configured": bool(settings.IPINFO_TOKEN),
            "mock_fallback_ready": True
        }
    }
