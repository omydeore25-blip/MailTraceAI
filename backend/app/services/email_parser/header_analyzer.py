import re
from typing import Dict, Any, List, Tuple, Optional, Union
from app.schemas.forensic_headers import HeaderForensicReport, ReceivedHop
from app.services.email_parser.eml_parser import extract_email_address


class HeaderAnalysisResult(tuple):
    """
    Dual-purpose result:
    1. Functions as a 2-tuple (report, spoofing_indicators) for unpacking:
       `headers_report, spoof_flags = analyze_headers(parsed, hops)`
    2. Directly delegates attributes to HeaderForensicReport for single-variable assignment:
       `header_report = analyze_headers(parsed['headers'], parsed['raw_headers'])`
    """
    def __new__(cls, report: HeaderForensicReport, spoofing_indicators: List[str]):
        return super().__new__(cls, (report, spoofing_indicators))

    def __init__(self, report: HeaderForensicReport, spoofing_indicators: List[str]):
        self.report = report
        self.spoofing_indicators = spoofing_indicators

    def __getattr__(self, name: str) -> Any:
        return getattr(self.report, name)


def analyze_headers(
    parsed_email: Dict[str, Any],
    hops: Optional[Union[List[ReceivedHop], str]] = None
) -> HeaderAnalysisResult:
    """Inspect email headers for forensic anomalies, spoofing indicators, and sender deception."""
    spoofing_indicators = []

    # 1. Normalize hops argument
    if isinstance(hops, list):
        hop_list: List[ReceivedHop] = hops
    else:
        hop_list = parsed_email.get("hops", []) if isinstance(parsed_email.get("hops"), list) else []

    # 2. Extract fields whether input is full parsed dict or raw headers map
    if "from_address" in parsed_email:
        from_addr = parsed_email.get("from_address", "")
        from_name = parsed_email.get("from_name", "")
        from_domain = parsed_email.get("from_domain", "")
        from_header = parsed_email.get("from_header", "")
        reply_to = parsed_email.get("reply_to")
        return_path = parsed_email.get("return_path")
        subject = parsed_email.get("subject", "")
        message_id = parsed_email.get("message_id", "")
        date = parsed_email.get("date")
        to_list = parsed_email.get("to", [])
        cc_list = parsed_email.get("cc", [])
        mailer_client = parsed_email.get("mailer_client")
    else:
        # Dictionary of raw headers
        raw_from = parsed_email.get("From", parsed_email.get("from", ""))
        from_header = raw_from
        from_name, from_addr = extract_email_address(raw_from)
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        
        raw_reply_to = parsed_email.get("Reply-To", parsed_email.get("reply-to"))
        _, reply_to = extract_email_address(raw_reply_to) if raw_reply_to else ("", None)
        
        raw_return_path = parsed_email.get("Return-Path", parsed_email.get("return-path"))
        _, return_path = extract_email_address(raw_return_path) if raw_return_path else ("", None)
        
        subject = parsed_email.get("Subject", parsed_email.get("subject", ""))
        message_id = parsed_email.get("Message-ID", parsed_email.get("message-id", ""))
        date = parsed_email.get("Date", parsed_email.get("date"))
        
        raw_to = parsed_email.get("To", parsed_email.get("to", ""))
        to_list = [extract_email_address(p)[1] for p in raw_to.split(",") if extract_email_address(p)[1]] if isinstance(raw_to, str) else []
        
        raw_cc = parsed_email.get("Cc", parsed_email.get("cc", ""))
        cc_list = [extract_email_address(p)[1] for p in raw_cc.split(",") if extract_email_address(p)[1]] if isinstance(raw_cc, str) else []
        
        mailer_client = parsed_email.get("User-Agent") or parsed_email.get("X-Mailer") or parsed_email.get("X-Originating-Mailer")

    # 3. Display Name Spoofing
    if from_name:
        embedded_emails = re.findall(r"[\w\.-]+@[\w\.-]+", from_name)
        if embedded_emails and embedded_emails[0].lower() != from_addr.lower():
            spoofing_indicators.append(
                f"Display Name Deception: Name contains '{embedded_emails[0]}' but actual envelope is '{from_addr}'"
            )
        
        # Check if display name pretends to be an executive or official service (CEO, IT Support, Helpdesk)
        executive_keywords = ["ceo", "cfo", "director", "helpdesk", "it support", "security alert", "admin", "microsoft 365", "google workspace"]
        lower_name = from_name.lower()
        for kw in executive_keywords:
            if kw in lower_name and ("gmail.com" in from_domain or "yahoo.com" in from_domain or "outlook.com" in from_domain):
                spoofing_indicators.append(
                    f"VIP/Service Impersonation: Name mentions '{kw.upper()}' but email uses generic free provider '{from_domain}'"
                )
                break

    # 4. Reply-To Mismatch
    if reply_to:
        reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
        if reply_domain and reply_domain != from_domain.lower():
            spoofing_indicators.append(
                f"Reply-To Mismatch: Responses will be routed to '{reply_to}' instead of sender '{from_addr}'"
            )

    # 5. Return-Path Mismatch
    if return_path:
        return_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""
        if return_domain and return_domain != from_domain.lower():
            spoofing_indicators.append(
                f"Return-Path Asymmetry: Bounce address domain '{return_domain}' differs from sender domain '{from_domain}'"
            )

    # 6. Message-ID Anomaly
    if not message_id:
        spoofing_indicators.append("Missing RFC 5322 Message-ID header (commonly stripped or omitted by spam mailers)")
    else:
        msg_id_domain = message_id.split("@")[-1].rstrip(">").strip().lower() if "@" in message_id else ""
        if msg_id_domain and from_domain and msg_id_domain != from_domain.lower() and not any(rel in msg_id_domain for rel in ["google.com", "protection.outlook.com", "sendgrid.net", "mailgun.org"]):
            spoofing_indicators.append(
                f"Message-ID Domain Discrepancy: Message-ID originated at '{msg_id_domain}' but sender claims '{from_domain}'"
            )

    # Calculate total transit time
    total_transit = sum(h.delay_seconds or 0 for h in hop_list)
    has_spoof = len(spoofing_indicators) > 0

    report = HeaderForensicReport(
        subject=subject,
        message_id=message_id,
        date=date,
        from_header=from_header,
        from_name=from_name,
        from_domain=from_domain,
        reply_to=reply_to or None,
        return_path=return_path or None,
        to=to_list,
        cc=cc_list,
        mailer_client=mailer_client,
        hops=hop_list,
        spoofing_indicators=spoofing_indicators,
        has_spoofed_headers=has_spoof,
        total_transit_time_seconds=total_transit
    )

    return HeaderAnalysisResult(report, spoofing_indicators)
