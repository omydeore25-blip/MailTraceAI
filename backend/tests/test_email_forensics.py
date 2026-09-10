import pytest
from app.services.email_parser.mime_parser import parse_raw_email
from app.services.email_parser.header_analyzer import analyze_headers
from app.services.email_parser.hop_analyzer import analyze_received_hops
from app.services.email_parser.attachment_inspector import inspect_attachments


def test_clean_newsletter_parsing(sample_emails):
    sample = sample_emails.get("clean_newsletter.eml")
    assert sample is not None, "Sample clean_newsletter.eml not found"
    
    parsed = parse_raw_email(sample["content"])
    assert "Tech Weekly" in parsed["subject"]
    assert "newsletter@techweekly.org" in parsed["from_header"]
    assert parsed["raw_headers"] is not None
    assert len(parsed["raw_headers"]) > 0

    header_report = analyze_headers(parsed["headers"], parsed["raw_headers"])
    assert header_report.has_spoofed_headers is False
    assert len(header_report.spoofing_indicators) == 0
    assert header_report.from_domain == "techweekly.org"

    hops = analyze_received_hops(parsed["received_headers"])
    assert len(hops) >= 2
    assert all(h.hop_number > 0 for h in hops)


def test_credential_phishing_forensics(sample_emails):
    sample = sample_emails.get("credential_phishing.eml")
    assert sample is not None, "Sample credential_phishing.eml not found"

    parsed = parse_raw_email(sample["content"])
    assert "Microsoft Account" in parsed["subject"]
    assert "admin@microsoft.com" in parsed["from_header"]

    header_report = analyze_headers(parsed["headers"], parsed["raw_headers"])
    # Return-Path or Reply-To mismatches the From domain
    assert header_report.has_spoofed_headers is True
    assert len(header_report.spoofing_indicators) > 0


def test_bec_wire_fraud_forensics(sample_emails):
    sample = sample_emails.get("bec_wire_fraud.eml")
    assert sample is not None, "Sample bec_wire_fraud.eml not found"

    parsed = parse_raw_email(sample["content"])
    assert "Wire Transfer" in parsed["subject"]

    header_report = analyze_headers(parsed["headers"], parsed["raw_headers"])
    assert "freemail-secure.com" in header_report.from_domain or "exec" in header_report.from_header


def test_dkim_spf_spoofed_clock_skew(sample_emails):
    sample = sample_emails.get("dkim_spf_spoofed.eml")
    assert sample is not None, "Sample dkim_spf_spoofed.eml not found"

    parsed = parse_raw_email(sample["content"])
    hops = analyze_received_hops(parsed["received_headers"])
    assert len(hops) >= 2

    # Check for anomaly detection or clock skew
    has_anomaly = any(h.anomalous for h in hops) or any("clock" in (h.anomaly_reason or "").lower() or "delay" in (h.anomaly_reason or "").lower() for h in hops)
    assert has_anomaly, "Spoofed email should trigger hop anomaly or delay warning"


def test_attachment_inspector_risk_hashing():
    fake_attachment = {
        "filename": "invoice_update.vbs",
        "content_type": "application/x-vbs",
        "size_bytes": 1024,
        "content_bytes": b"WScript.Echo 'Testing malicious attachment'"
    }
    inspected = inspect_attachments([fake_attachment])
    assert len(inspected) == 1
    att = inspected[0]
    assert att.filename == "invoice_update.vbs"
    assert att.is_executable_or_script is True
    assert att.sha256 != ""
    assert att.md5 != ""
    assert att.risk_level in ["high", "critical"]
