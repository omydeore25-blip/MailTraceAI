import io
from typing import Dict, Any, List
from app.core.exceptions import EmailParsingError
from app.services.email_parser.eml_parser import parse_raw_eml


def parse_raw_msg(content: bytes) -> Dict[str, Any]:
    """Parse Outlook .msg binary file using extract_msg or fallback."""
    try:
        import extract_msg
        msg = extract_msg.Message(io.BytesIO(content))
        
        # Convert extract_msg fields to normalized dict
        subject = msg.subject or ""
        from_header = msg.sender or ""
        from_address = ""
        from_name = ""
        
        if "<" in from_header and ">" in from_header:
            from_name = from_header.split("<")[0].strip().strip('"')
            from_address = from_header.split("<")[1].split(">")[0].strip().lower()
        else:
            from_address = from_header.strip().lower()
            
        from_domain = from_address.split("@")[-1] if "@" in from_address else ""
        
        to_list = [r.strip() for r in (msg.to or "").split(";") if r.strip()]
        cc_list = [r.strip() for r in (msg.cc or "").split(";") if r.strip()]
        
        raw_headers = msg.header or ""
        received_headers = []
        if raw_headers:
            for line in raw_headers.splitlines():
                if line.lower().startswith("received:"):
                    received_headers.append(line.split(":", 1)[1].strip())
                    
        return {
            "subject": subject,
            "from_header": from_header,
            "from_name": from_name,
            "from_address": from_address,
            "from_domain": from_domain,
            "reply_to": None,
            "return_path": None,
            "to": to_list,
            "cc": cc_list,
            "date": str(msg.date or ""),
            "message_id": msg.messageId or "",
            "mailer_client": "Microsoft Outlook",
            "raw_headers": raw_headers,
            "received_headers": received_headers,
            "body_plain": msg.body or "",
            "body_html": msg.htmlBody.decode("utf-8", errors="replace") if isinstance(msg.htmlBody, bytes) else (msg.htmlBody or ""),
            "attachments": []
        }
    except ImportError:
        # Fallback if extract_msg is not installed in current environment
        raise EmailParsingError("The extract-msg module is required to parse Outlook .msg files. Please convert to .eml or install extract-msg.")
    except Exception as e:
        raise EmailParsingError(f"Failed to parse Outlook .msg file: {str(e)}")
