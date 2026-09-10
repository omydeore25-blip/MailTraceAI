import asyncio
import os
import sys

# Ensure backend directory in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.db.base import Base
from app.db.session import engine, AsyncSessionLocal
from app.api.v1.analysis import execute_forensic_pipeline

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "data", "samples")

SAMPLE_FILES = [
    "clean_newsletter.eml",
    "credential_phishing.eml",
    "bec_wire_fraud.eml",
    "dkim_spf_spoofed.eml"
]


async def seed_database():
    print("==========================================================")
    print(" MAILTRACE AI — SEEDING BENCHMARK FORENSIC CASES")
    print("==========================================================\n")

    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        for filename in SAMPLE_FILES:
            filepath = os.path.join(SAMPLES_DIR, filename)
            if not os.path.exists(filepath):
                print(f"[!] Warning: Sample file {filename} not found.")
                continue

            with open(filepath, "rb") as f:
                content = f.read()

            print(f"[*] Ingesting and analyzing: {filename}...")
            result = await execute_forensic_pipeline(content, filename=filename, db=session)
            print(f"    -> Case ID: {result.id}")
            print(f"    -> Subject: {result.subject}")
            print(f"    -> Sender: {result.sender}")
            print(f"    -> Score: {result.risk_score}/100 ({result.threat_level})")
            print(f"    -> Intent: {result.ai_insights.get('primary_category')}")
            print(f"    -> Attributed Campaign: {result.campaign_id}")
            print("    [SAVED TO DATABASE]\n")

    print("[SUCCESS] All sample benchmark cases successfully seeded into database!")


if __name__ == "__main__":
    asyncio.run(seed_database())
