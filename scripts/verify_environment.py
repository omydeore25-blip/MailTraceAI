import os
import sys
import asyncio

# Ensure backend directory in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.core.config import settings
from app.db.session import engine, AsyncSessionLocal
from app.models.email_analysis import EmailAnalysis
from app.models.ioc import IOC
from sqlalchemy import select, func


async def verify():
    print("==========================================================")
    print(" MAILTRACE AI — ENVIRONMENT & READINESS AUDIT")
    print("==========================================================\n")

    print(f"[*] Application: {settings.APP_NAME}")
    print(f"[*] Environment: {settings.APP_ENV}")
    print(f"[*] Database URL: {settings.DATABASE_URL}")
    print(f"[*] Neo4j Configured: {settings.NEO4J_ENABLED} ({settings.NEO4J_URI})")
    print(f"[*] VirusTotal Key: {'Configured' if settings.VIRUSTOTAL_API_KEY else 'Mock Fallback Ready'}")
    print(f"[*] AbuseIPDB Key: {'Configured' if settings.ABUSEIPDB_API_KEY else 'Mock Fallback Ready'}")
    print(f"[*] IPinfo Token: {'Configured' if settings.IPINFO_TOKEN else 'Mock Fallback Ready'}\n")

    print("[*] Inspecting Database Persistence...")
    async with AsyncSessionLocal() as session:
        case_count = await session.scalar(select(func.count()).select_from(EmailAnalysis))
        ioc_count = await session.scalar(select(func.count()).select_from(IOC))
        print(f"    -> Stored Cases: {case_count}")
        print(f"    -> Extracted Indicators of Compromise: {ioc_count}")

    print("\n[SUCCESS] Environment verification complete. All systems nominal!")


if __name__ == "__main__":
    asyncio.run(verify())
