from typing import Dict, Any, List
from app.services.ioc_extractor.url_extractor import extract_urls, defang_url
from app.services.ioc_extractor.ip_domain_extractor import extract_ips, extract_domains, defang_ip, defang_domain
from app.services.ioc_extractor.typosquatting import detect_typosquatting
from app.schemas.ioc import ExtractedIOCs, IOCItem, AttachmentMeta


def extract_all_iocs(parsed_email: Dict[str, Any], hop_ips: List[str] = None) -> ExtractedIOCs:
    """Extract and analyze all indicators of compromise (URLs, IPs, Domains, Attachments)."""
    plain_body = parsed_email.get("body_plain", "")
    html_body = parsed_email.get("body_html", "")
    full_text = f"{plain_body} {html_body} {parsed_email.get('subject', '')}"

    # 1. URLs
    urls = extract_urls(plain_body=plain_body, html_body=html_body)

    # 2. Domains
    url_strings = [u.value for u in urls]
    domains = extract_domains(urls=url_strings, text=full_text)
    
    # Also include sender domain
    sender_domain = parsed_email.get("from_domain")
    if sender_domain and not any(d.value == sender_domain for d in domains):
        domains.append(IOCItem(
            ioc_type="domain",
            value=sender_domain,
            defanged_value=defang_domain(sender_domain),
            reputation_score=0.0,
            is_malicious=False,
            enrichment={}
        ))

    # Evaluate typosquatting for each domain
    for d in domains:
        typo_info = detect_typosquatting(d.value)
        if typo_info:
            d.reputation_score = typo_info["risk_score"]
            d.is_malicious = typo_info["risk_score"] >= 70.0
            d.enrichment["typosquatting"] = typo_info

    # 3. IPs
    ips = extract_ips(text=full_text, hop_ips=hop_ips)

    # 4. Attachments
    attachments = parsed_email.get("attachments", [])

    # Calculate totals
    total_count = len(urls) + len(ips) + len(domains) + len(attachments)
    malicious_count = (
        sum(1 for u in urls if u.is_malicious) +
        sum(1 for i in ips if i.is_malicious) +
        sum(1 for d in domains if d.is_malicious) +
        sum(1 for a in attachments if a.risk_level in ["High", "Critical"])
    )

    return ExtractedIOCs(
        urls=urls,
        ips=ips,
        domains=domains,
        attachments=attachments,
        total_iocs_found=total_count,
        malicious_iocs_count=malicious_count
    )
