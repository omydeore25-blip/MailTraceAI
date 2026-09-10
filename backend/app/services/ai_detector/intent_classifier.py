from typing import Dict, Any, List
from app.services.ai_detector.heuristic_rules import extract_linguistic_heuristics


def classify_email_intent(
    subject: str,
    plain_body: str,
    html_body: str,
    has_malicious_attachment: bool = False,
    has_malicious_url: bool = False,
    is_spoofed: bool = False
) -> Dict[str, Any]:
    """
    Classify the psychological and adversarial intent behind an email message.
    """
    heuristics = extract_linguistic_heuristics(subject=subject, plain_body=plain_body, html_body=html_body)

    fin_score = heuristics["financial_score"]
    cred_score = heuristics["credential_score"]
    urg_score = heuristics["urgency_score"]
    base_score = heuristics["heuristic_score"]

    primary_category = "Clean / Legitimate Communication"
    confidence = 0.90
    explanation = "No adversarial or deceptive patterns detected in the message contents."
    psychological_levers = []

    if urg_score > 0:
        psychological_levers.append("Artificial Urgency")
    if heuristics["authority_score"] > 0:
        psychological_levers.append("Coercive Authority")

    # Intent Decision Tree
    if has_malicious_attachment:
        primary_category = "Malware Carrier / Weaponized Payload"
        confidence = 0.95
        explanation = "Message delivers a suspicious or weaponized attachment payload intended to compromise endpoints."
        psychological_levers.append("Curiosity / Deception")

    elif fin_score >= 50 or (fin_score > 0 and is_spoofed):
        primary_category = "Business Email Compromise (BEC) / Wire Fraud"
        confidence = 0.92 if is_spoofed else 0.85
        explanation = "Sender attempts to redirect funds, modify payroll or invoice records, or request executive-level financial transactions."
        psychological_levers.append("Financial Deception")

    elif cred_score >= 50 or has_malicious_url:
        primary_category = "Credential Harvesting Phishing"
        confidence = 0.94 if has_malicious_url else 0.88
        explanation = "Message is engineered to coerce the recipient into entering login credentials, SSO tokens, or authentication credentials on a spoofed portal."
        psychological_levers.append("Credential Harvesting")

    elif is_spoofed:
        primary_category = "Brand / Identity Impersonation"
        confidence = 0.85
        explanation = "Sender exhibits significant header or display-name forgery to disguise true sender origin."
        psychological_levers.append("Identity Impersonation")

    elif base_score >= 40:
        primary_category = "Suspicious Social Engineering"
        confidence = 0.75
        explanation = "Message contains multiple high-pressure urgency and persuasion markers characteristic of phishing lures."

    return {
        "primary_category": primary_category,
        "confidence": confidence,
        "explanation": explanation,
        "psychological_levers": psychological_levers,
        "linguistic_heuristics": heuristics
    }
