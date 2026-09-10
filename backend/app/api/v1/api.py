from fastapi import APIRouter
from app.api.v1 import auth, health, analysis, threat_intel, graph, reports

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["Email Analysis"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(graph.router, prefix="/graph", tags=["Infrastructure Graph"])
api_router.include_router(reports.router, prefix="/reports", tags=["Forensic Reports"])
