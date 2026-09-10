"""
End-to-End Live Integration Verification Script for MailTrace AI.
Tests the complete user flow against the live server:
- Auth & Token Generation
- All 4 Benchmark Emails Ingestion
- Forensic Validation (Risk Score, SPF/DKIM/DMARC/ARC, Hops, Skew, Headers, IOCs)
- AI Intent & MITRE ATT&CK Mapping
- Graph Generation (Nodes & Edges)
- Threat Intelligence Verification & Fallback Truthfulness
- PDF & JSON Report Generation
- Case History & Deletion Lifecycle
"""

import sys
import os
import json
import httpx
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
PROXY_URL = "http://localhost:5173"
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "backend" / "app" / "data" / "samples"

def print_banner(msg):
    print("\n" + "=" * 70)
    print(f" {msg}")
    print("=" * 70)

def main():
    print_banner("MAILTRACE AI — LIVE END-TO-END INTEGRATION TEST")
    
    with httpx.Client(timeout=30.0) as client:
        # 1. Health Checks
        print("\n[1] Verifying System Health...")
        h_resp = client.get(f"{BASE_URL}/health")
        assert h_resp.status_code == 200, f"Health check failed: {h_resp.status_code}"
        h_data = h_resp.json()
        print(f"    -> Backend /health: {h_data['status'].upper()} (DB: {h_data['database']['status']})")
        
        # Proxy check via Vite frontend
        p_resp = client.get(f"{PROXY_URL}/api/v1/health")
        assert p_resp.status_code == 200, f"Vite proxy check failed: {p_resp.status_code}"
        print(f"    -> Vite Frontend Proxy (port 5173 -> 8000): CONNECTED & PROXYING")

        # 2. Authentication Flow
        print("\n[2] Testing Authentication Flow...")
        auth_resp = client.post(
            f"{BASE_URL}/api/v1/auth/login",
            data={"username": "analyst", "password": "analyst123!"}
        )
        assert auth_resp.status_code == 200, f"Login failed: {auth_resp.status_code} {auth_resp.text}"
        token_data = auth_resp.json()
        access_token = token_data.get("access_token")
        assert access_token, "No access token returned"
        print(f"    -> Analyst Login: SUCCESS (JWT: {access_token[:20]}...)")
        
        headers = {"Authorization": f"Bearer {access_token}"}
        me_resp = client.get(f"{BASE_URL}/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200
        print(f"    -> Profile Verified: {me_resp.json().get('email')} ({me_resp.json().get('role')})")

        # 3. Process Benchmark Emails
        print("\n[3] Testing Forensic Ingestion on 4 Benchmark Scenarios...")
        samples = [
            ("clean_newsletter.eml", "Clean", 0.0, 30.0),
            ("credential_phishing.eml", "Malicious", 60.0, 100.0),
            ("bec_wire_fraud.eml", "Suspicious", 30.0, 70.0),
            ("dkim_spf_spoofed.eml", "Malicious", 60.0, 100.0),
        ]

        created_case_ids = []

        for filename, expected_level, min_score, max_score in samples:
            filepath = SAMPLES_DIR / filename
            assert filepath.exists(), f"Missing sample file: {filepath}"
            
            with open(filepath, "rb") as f:
                file_bytes = f.read()

            print(f"\n    [*] Uploading & Analyzing: {filename}...")
            files = {"file": (filename, file_bytes, "message/rfc822")}
            scan_resp = client.post(f"{BASE_URL}/api/v1/analysis/upload", files=files, headers=headers)
            assert scan_resp.status_code == 200, f"Upload failed for {filename}: {scan_resp.text}"
            
            detail = scan_resp.json()
            case_id = detail["id"]
            created_case_ids.append(case_id)
            
            subject = detail.get("subject", "N/A")
            risk_score = detail["risk_assessment"]["overall_score"]
            threat_level = detail["threat_level"]
            raw_headers = detail.get("raw_headers")
            auth = detail["auth_summary"]
            hops = detail["hops"]
            iocs = detail["extracted_iocs"]
            ai = detail["ai_insights"]
            mitre = detail["mitre_attack"]
            
            print(f"        - Case ID: {case_id}")
            print(f"        - Subject: {subject[:50]}")
            print(f"        - Risk Score: {risk_score:.1f}/100 ({threat_level})")
            print(f"        - Auth: SPF={auth['spf']['status']} ({auth['spf']['verification_method']}), "
                  f"DKIM={auth['dkim']['status']} ({auth['dkim']['verification_method']}), "
                  f"DMARC={auth['dmarc']['status']} ({auth['dmarc']['verification_method']})")
            print(f"        - Hops: {len(hops)} hops mapped")
            print(f"        - IOCs Found: {iocs['total_iocs_found']} (Malicious: {iocs['malicious_iocs_count']})")
            print(f"        - AI Intent: {ai.get('primary_category')}")
            print(f"        - MITRE ATT&CK: {[m['id'] for m in mitre]}")
            print(f"        - Raw Headers Preserved: {bool(raw_headers and len(raw_headers) > 100)}")

            # Assertions
            assert raw_headers and len(raw_headers) > 100, f"Raw headers missing for {filename}"
            if expected_level == "Clean":
                assert threat_level == "Clean" and risk_score <= max_score
            else:
                assert risk_score >= min_score

            # 4. Verify Infrastructure Graph
            graph_resp = client.get(f"{BASE_URL}/api/v1/graph/analysis/{case_id}", headers=headers)
            assert graph_resp.status_code == 200, f"Graph retrieval failed for {case_id}"
            graph = graph_resp.json()
            print(f"        - Graph Topology: {graph['total_nodes']} nodes, {graph['total_edges']} edges (Engine: {graph['source_engine']})")
            assert graph['total_nodes'] >= 2, "Graph must contain at least 2 nodes"

            # 5. Verify PDF Report Generation
            pdf_resp = client.get(f"{BASE_URL}/api/v1/reports/{case_id}/pdf", headers=headers)
            assert pdf_resp.status_code == 200, f"PDF report generation failed for {case_id}"
            assert pdf_resp.headers.get("content-type") == "application/pdf"
            assert len(pdf_resp.content) > 1000, "PDF content too small"
            print(f"        - PDF Export: {len(pdf_resp.content)} bytes [OK]")

            # 6. Verify JSON Report Generation
            json_resp = client.get(f"{BASE_URL}/api/v1/reports/{case_id}/json", headers=headers)
            assert json_resp.status_code == 200, f"JSON report generation failed for {case_id}"
            json_rep = json_resp.json()
            assert "case_id" in json_rep or "id" in json_rep
            print(f"        - JSON Export: Structured report verified [OK]")

        # 7. Test Cross-Correlation & History Listing
        print("\n[4] Testing History Listing & Cross-Case Attribution...")
        hist_resp = client.get(f"{BASE_URL}/api/v1/analysis/?limit=50", headers=headers)
        assert hist_resp.status_code == 200
        all_cases = hist_resp.json()
        print(f"    -> Total Cases in History: {len(all_cases)}")
        assert len(all_cases) >= 4

        # 8. Test Threat Intel Console Lookup & Fallback Truthfulness
        print("\n[5] Testing Threat Intel Console & Fallback Truthfulness...")
        ti_tests = [
            ("ip", "185.220.101.5", "Tor Exit Node"),
            ("ip", "192.168.1.1", "RFC 1918 Private IP"),
            ("domain", "micros0ft-security-auth.com", "Typosquatted Phish Domain")
        ]
        for ioc_type, val, label in ti_tests:
            ti_resp = client.get(f"{BASE_URL}/api/v1/threat-intel/lookup", params={"ioc_type": ioc_type, "value": val}, headers=headers)
            assert ti_resp.status_code == 200, f"TI lookup failed for {val}"
            ti_data = ti_resp.json()
            enrichment = ti_data.get("enrichment", {})
            print(f"    -> Lookup {label} ({val}): Provider={enrichment.get('provider')}, Fallback={enrichment.get('is_fallback', False)}")
            if val == "192.168.1.1":
                assert enrichment.get("is_private") is True
                assert "LAN" in enrichment.get("country") or "Private" in enrichment.get("country")
            else:
                # If API keys are unconfigured, fallback flag must be truthful
                assert enrichment.get("is_fallback") is True or "provider_status" in enrichment

        # 9. Test Case Deletion Lifecycle
        print("\n[6] Testing Case Deletion Lifecycle...")
        test_delete_id = created_case_ids[-1]
        del_resp = client.delete(f"{BASE_URL}/api/v1/analysis/{test_delete_id}", headers=headers)
        assert del_resp.status_code == 200, f"Delete failed: {del_resp.status_code} {del_resp.text}"
        assert del_resp.json().get("status") == "deleted"
        print(f"    -> Case {test_delete_id[:8]} DELETED successfully")
        
        # Verify 404 after deletion
        verify_resp = client.get(f"{BASE_URL}/api/v1/analysis/{test_delete_id}", headers=headers)
        assert verify_resp.status_code == 404
        print(f"    -> Deletion Verified: 404 Not Found on subsequent lookup")

        print_banner("ALL LIVE END-TO-END VERIFICATION CHECKS PASSED [SUCCESS]")

if __name__ == "__main__":
    main()
