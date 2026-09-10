"""
Attachment Inspector module for forensic hashing and risk assessment.
"""
import hashlib
from typing import List, Dict, Any, Union
from app.schemas.ioc import AttachmentMeta
from app.services.email_parser.eml_parser import (
    DANGEROUS_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    MACRO_EXTENSIONS,
    safe_decode_header
)


def inspect_attachments(attachments: List[Union[Dict[str, Any], AttachmentMeta]]) -> List[AttachmentMeta]:
    """
    Inspect raw attachments, calculate cryptographic hashes (MD5, SHA1, SHA256),
    and evaluate security risk levels.
    """
    inspected: List[AttachmentMeta] = []

    for item in attachments:
        if isinstance(item, AttachmentMeta):
            inspected.append(item)
            continue

        filename = safe_decode_header(item.get("filename", "unnamed_attachment"))
        content_type = str(item.get("content_type", "application/octet-stream")).lower()
        payload = item.get("content_bytes") or item.get("payload") or b""
        size_bytes = item.get("size_bytes", len(payload))

        md5_hash = hashlib.md5(payload).hexdigest()
        sha1_hash = hashlib.sha1(payload).hexdigest()
        sha256_hash = hashlib.sha256(payload).hexdigest()

        file_ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        is_exec = file_ext in DANGEROUS_EXTENSIONS
        is_arch = file_ext in ARCHIVE_EXTENSIONS
        is_macro = file_ext in MACRO_EXTENSIONS

        risk_flags: List[str] = []
        risk_level = "low"

        if is_exec:
            risk_flags.append(f"Executable/Script extension: {file_ext}")
            risk_level = "critical"
        elif is_macro:
            risk_flags.append("Macro-enabled document format")
            risk_level = "high"
        elif is_arch:
            risk_flags.append("Archive payload; potential nested executable carrier")
            risk_level = "medium"

        if ".." in filename or filename.count(".") > 1:
            risk_flags.append("Double extension / obfuscated file name detected")
            risk_level = "high"

        inspected.append(AttachmentMeta(
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

    return inspected
