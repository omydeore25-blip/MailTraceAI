import pytest
from app.services.ai_detector.intent_classifier import classify_email_intent
from app.services.ai_detector.risk_scorer import compute_risk_score
from app.services.attribution.mitre_mapper import map_mitre_attack_techniques
from app.services.email_parser.mime_parser import parse_raw_email
from app.services.email_parser.header_analyzer import analyze_headers
from app.services.email_parser.hop_analyzer import analyze_received_hops
from app.services.authentication import audit_authentication
from app.schemas.ioc import ExtractedIOCs, IOCItem, AttachmentMeta


def test_classify_clean_email():
    intent = classify_email_intent(
        subject="Monthly Engineering Newsletter",
        plain_body="Here is our roundup of open source developments this month. Hope you find it useful!",
        html_body="",
        has_malicious_attachment=False,
        has_malicious_url=False,
        is_spoofed=False
    )
    assert intent["primary_category"] == "Clean / Legitimate Communication"
    assert intent["confidence"] >= 0.80


def test_classify_bec_wire_fraud():
    intent = classify_email_intent(
        subject="Strictly Confidential: Wire Transfer Request",
        plain_body="Please process an urgent wire transfer for the acquisition immediately. Do not discuss with anyone else.",
        html_body="",
        has_malicious_attachment=False,
        has_malicious_url=False,
        is_spoofed=True
    )
    assert "Business Email Compromise" in intent["primary_category"] or "Wire Fraud" in intent["primary_category"]
    assert "Artificial Urgency" in intent["psychological_levers"]


def test_classify_credential_phishing():
    intent = classify_email_intent(
        subject="[ALERT] Unauthorized Password Reset Request",
        plain_body="Someone attempted to login to your Microsoft Account. Click here to verify your identity and reset your credentials immediately.",
        html_body="<a href='http://evil-login-portal.cc'>Verify</a>",
        has_malicious_attachment=False,
        has_malicious_url=True,
        is_spoofed=True
    )
    assert "Credential Harvesting" in intent["primary_category"] or "Phishing" in intent["primary_category"]


def test_classify_malware_attachment():
    intent = classify_email_intent(
        subject="Overdue Invoice Attached",
        plain_body="Please inspect the attached invoice.",
        html_body="",
        has_malicious_attachment=True,
        has_malicious_url=False,
        is_spoofed=False
    )
    assert "Malware Carrier" in intent["primary_category"] or "Payload" in intent["primary_category"]


def test_risk_scorer_clean_vs_malicious(sample_emails):
    clean_sample = sample_emails.get("clean_newsletter.eml")
    assert clean_sample is not None

    parsed_clean = parse_raw_email(clean_sample["content"])
    header_report = analyze_headers(parsed_clean["headers"], parsed_clean["raw_headers"])
    auth_summary = audit_authentication(from_domain="techweekly.org", client_ip="198.51.100.15", raw_headers=parsed_clean["raw_headers"])
    clean_iocs = ExtractedIOCs(urls=[], ips=[], domains=[], attachments=[], total_iocs_found=0, malicious_iocs_count=0)
    clean_intent = classify_email_intent(parsed_clean["subject"], parsed_clean["body_plain"], parsed_clean["body_html"])

    risk_clean = compute_risk_score(header_report, auth_summary, clean_iocs, clean_intent)
    assert risk_clean.overall_score < 30.0
    assert risk_clean.threat_level == "Clean"
    assert len(risk_clean.factors) == 5
    # Total weights must equal 100%
    total_weights = sum(f.weight_percentage for f in risk_clean.factors)
    assert total_weights == 100

    # Phishing sample
    phish_sample = sample_emails.get("credential_phishing.eml")
    assert phish_sample is not None

    parsed_phish = parse_raw_email(phish_sample["content"])
    header_report_phish = analyze_headers(parsed_phish["headers"], parsed_phish["raw_headers"])
    auth_summary_phish = audit_authentication(from_domain="microsoft.com", client_ip="185.220.101.5", raw_headers=parsed_phish["raw_headers"])
    phish_iocs = ExtractedIOCs(
        urls=[IOCItem(ioc_type="url", value="http://login-verify-account.top", defanged_value="hxxp://login-verify-account[.]top", reputation_score=95, is_malicious=True, enrichment={})],
        ips=[],
        domains=[],
        attachments=[],
        total_iocs_found=1,
        malicious_iocs_count=1
    )
    phish_intent = classify_email_intent(parsed_phish["subject"], parsed_phish["body_plain"], parsed_phish["body_html"], has_malicious_url=True, is_spoofed=True)

    risk_phish = compute_risk_score(header_report_phish, auth_summary_phish, phish_iocs, phish_intent)
    assert risk_phish.overall_score >= 60.0
    assert risk_phish.threat_level in ["Malicious", "Critical"]


def test_mitre_attack_mapping():
    from app.schemas.forensic_headers import HeaderForensicReport
    from app.schemas.authentication import AuthSummary, SPFResult, DKIMResult, DMARCResult, ARCResult

    headers_rep = HeaderForensicReport(
        subject="Urgent action",
        message_id="123",
        date="today",
        from_header="admin@bank.com",
        from_name="Bank Admin",
        from_domain="bank.com",
        reply_to="attacker@evil.com",
        return_path="bounce@attacker.com",
        to=["victim@org.com"],
        cc=[],
        mailer_client="Outlook",
        hops=[],
        spoofing_indicators=["Sender mismatch"],
        has_spoofed_headers=True,
        total_transit_time_seconds=10
    )
    auth_sum = AuthSummary(
        spf=SPFResult(status="fail"),
        dkim=DKIMResult(status="fail"),
        dmarc=DMARCResult(status="fail"),
        arc=ARCResult(status="none"),
        overall_authenticated=False,
        failure_reasons=["DMARC fail"]
    )
    iocs = ExtractedIOCs(
        urls=[IOCItem(ioc_type="url", value="http://malicious.ru/login", defanged_value="hxxp://malicious[.]ru/login", reputation_score=90, is_malicious=True, enrichment={})],
        ips=[],
        domains=[],
        attachments=[],
        total_iocs_found=1,
        malicious_iocs_count=1
    )
    intent = {"primary_category": "Credential Harvesting Phishing"}

    techniques = map_mitre_attack_techniques(headers_rep, auth_sum, iocs, intent)
    assert len(techniques) > 0
    technique_ids = [t["id"] for t in techniques]
    assert "T1566.002" in technique_ids # Spearphishing link
