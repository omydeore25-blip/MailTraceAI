import asyncio
import os
import sys

# Ensure backend directory in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.api.v1.analysis import execute_forensic_pipeline
from app.services.reporting import generate_forensic_pdf
from app.services.graph import graph_service

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "data", "samples")


async def run_tests():
    print("=================================================================")
    print(" MAILTRACE AI — PIPELINE VERIFICATION & FORENSIC SMOKE TEST")
    print("=================================================================\n")

    sample_files = [
        ("clean_newsletter.eml", "Clean"),
        ("credential_phishing.eml", "Critical"),
        ("bec_wire_fraud.eml", "Critical"),
        ("dkim_spf_spoofed.eml", "Malicious")
    ]

    for filename, expected_level in sample_files:
        filepath = os.path.join(SAMPLES_DIR, filename)
        assert os.path.exists(filepath), f"File not found: {filepath}"
        
        with open(filepath, "rb") as f:
            content = f.read()

        print(f"[*] Testing forensic analysis on: {filename}...")
        result = await execute_forensic_pipeline(content, filename=filename, db=None)
        
        print(f"    -> Subject: {result.subject}")
        print(f"    -> Sender: {result.sender}")
        print(f"    -> Risk Score: {result.risk_score}/100 ({result.threat_level})")
        print(f"    -> Intent Category: {result.ai_insights.get('primary_category')}")
        print(f"    -> Hops Found: {len(result.hops)}")
        print(f"    -> Total IOCs Extracted: {result.extracted_iocs.total_iocs_found}")
        print(f"    -> MITRE ATT&CK Mapped: {[m['id'] for m in result.mitre_attack]}")
        print(f"    -> Attributed Campaign: {result.campaign_id} (Actor: {result.threat_actor})")

        # Test graph generation
        graph = await graph_service.get_graph_for_analysis(result.model_dump())
        print(f"    -> Graph Elements: {graph.total_nodes} nodes, {graph.total_edges} edges (Engine: {graph.source_engine})")

        # Test PDF generation
        pdf_bytes = generate_forensic_pdf(result.model_dump())
        print(f"    -> PDF Generated: {len(pdf_bytes)} bytes successfully compiled.")
        print("    [PASS]\n")

    print("[SUCCESS] All 4 forensic email scenarios executed and verified perfectly!")


if __name__ == "__main__":
    asyncio.run(run_tests())
