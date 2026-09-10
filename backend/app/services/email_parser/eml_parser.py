import email
from email import policy
from email.header import decode_header
from email.message import EmailMessage
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from app.core.exceptions import EmailParsingError
from app.schemas.ioc import AttachmentMeta

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".hta", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd",
    ".ps1", ".iso", ".img", ".vhd", ".docm", ".xlsm", ".pptm", ".dotm",
    ".iqy", ".slk", ".jar", ".cpl", ".inf", ".reg"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}


def safe_decode_header(header_value: Optional[str]) -> str:
    """Safely decode RFC 2047 encoded email headers."""
    if not header_value:
        return ""
    try:
        decoded_parts = decode_header(header_value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                encoding = charset or "utf-8"
                try:
                    result.append(part.decode(encoding, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    result.append(part.decode("latin-1", errors="replace"))
            else:
                result.append(str(part))
        return " ".join(result).strip()
    except Exception:
        return str(header_value)


def extract_email_address(addr_str: Optional[str]) -> Tuple[str, str]:
    """Extract (display_name, email_address) from string like 'John Doe <john@example.com>'."""
    if not addr_str:
        return "", ""
    decoded = safe_decode_header(addr_str)
    match = re.search(r"<([^>]+)>", decoded)
    if match:
        email_addr = match.group(1).strip()
        display_name = decoded.replace(f"<{email_addr}>", "").strip().strip('"').strip("'")
        return display_name, email_addr.lower()
    # Simple address without brackets
    addr = decoded.strip().strip('"').strip("'").lower()
    return "", addr


def parse_raw_eml(content: Any) -> Dict[str, Any]:
    """Parse raw bytes or string of an .eml message into structured forensic data."""
    if isinstance(content, str):
        content_bytes = content.encode("utf-8", errors="replace")
    else:
        content_bytes = bytes(content)

    try:
        msg = email.message_from_bytes(content_bytes, policy=policy.default)
    except Exception as e:
        raise EmailParsingError(f"Failed to parse MIME message: {str(e)}")

    subject = safe_decode_header(msg.get("Subject", ""))
    raw_from = msg.get("From", "")
    from_name, from_address = extract_email_address(raw_from)
    from_domain = from_address.split("@")[-1] if "@" in from_address else ""

    raw_reply_to = msg.get("Reply-To", "")
    _, reply_to_address = extract_email_address(raw_reply_to)


    raw_return_path = msg.get("Return-Path", "")
    _, return_path_address = extract_email_address(raw_return_path)

    # Recipients (To, CC, BCC)
    to_list = []
    if msg.get("To"):
        for part in msg.get("To").split(","):
            _, addr = extract_email_address(part)
            if addr:
                to_list.append(addr)

    cc_list = []
    if msg.get("Cc"):
        for part in msg.get("Cc").split(","):
            _, addr = extract_email_address(part)
            if addr:
                cc_list.append(addr)

    date_str = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    mailer_client = msg.get("User-Agent") or msg.get("X-Mailer") or msg.get("X-Originating-Mailer")

    # Body extraction & attachment processing
    body_plain_parts = []
    body_html_parts = []
    attachments = []

    for part in msg.walk():
        content_disposition = str(part.get_content_disposition() or "").lower()
        content_type = str(part.get_content_type() or "").lower()
        filename = part.get_filename()

        if filename:
            filename = safe_decode_header(filename)

        is_attachment = content_disposition == "attachment" or (filename is not None and content_disposition != "inline")

        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            size_bytes = len(payload)
            md5_hash = hashlib.md5(payload).hexdigest()
            sha1_hash = hashlib.sha1(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            file_ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            is_exec = file_ext in DANGEROUS_EXTENSIONS
            is_arch = file_ext in ARCHIVE_EXTENSIONS
            is_macro = file_ext in MACRO_EXTENSIONS

            risk_flags = []
            risk_level = "Low"

            if is_exec:
                risk_flags.append(f"Executable/Script extension: {file_ext}")
                risk_level = "Critical"
            if is_macro:
                risk_flags.append("Macro-enabled document format")
                risk_level = "High"
            if is_arch:
                risk_flags.append("Archive payload; potential nested executable carrier")
                if risk_level == "Low":
                    risk_level = "Medium"
            if ".." in filename or filename.count(".") > 1:
                risk_flags.append("Double extension / obfuscated file name detected")
                risk_level = "High"

            attachments.append(AttachmentMeta(
                filename=filename,
                content_type=content_type,
                size_bytes=size_bytes,
                md5=md5_hash,
                sha1=sha1_hash,
                sha256=sha256_hash,
                is_executable_or_script=is_exec,
                is_archive=is_arch,
                is_macro_enabled=is_macro,
                risk_level=risk_level,
                risk_flags=risk_flags
            ))
        else:
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_plain_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_html_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass

    body_plain = "\n\n".join(body_plain_parts).strip()
    body_html = "\n\n".join(body_html_parts).strip()

    # Raw headers string and headers dictionary
    raw_headers = []
    headers_dict = {}
    for header, value in msg.items():
        raw_headers.append(f"{header}: {value}")
        headers_dict[header] = str(value)
    raw_headers_str = "\n".join(raw_headers)

    # Received headers list (as preserved raw strings)
    received_headers = msg.get_all("Received", [])

    return {
        "subject": subject,
        "from_header": raw_from,
        "from_name": from_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to": reply_to_address if reply_to_address else None,
        "return_path": return_path_address if return_path_address else None,
        "to": to_list,
        "cc": cc_list,
        "date": date_str,
        "message_id": message_id,
        "mailer_client": mailer_client,
        "headers": headers_dict,
        "raw_headers": raw_headers_str,
        "received_headers": received_headers,
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": attachments
    }

