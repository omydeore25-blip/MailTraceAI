import re
from datetime import datetime, timezone
import email.utils
from typing import List, Dict, Any, Optional
from app.schemas.forensic_headers import ReceivedHop

# Regex patterns for Received header analysis
IP_REGEX = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:\.]+)\]|(?:from|by)\s+.*?([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
FROM_REGEX = re.compile(r"from\s+([^\s\(\)]+)", re.IGNORECASE)
BY_REGEX = re.compile(r"by\s+([^\s\(\)]+)", re.IGNORECASE)


def parse_received_hops(received_headers: List[str]) -> List[ReceivedHop]:
    """
    Parse email 'Received' headers into a chronological timeline from origin to destination.
    In MIME, headers are prepended, so the bottom header is the first hop (origin).
    """
    if not received_headers:
        return []

    # Chronological order: reverse the list so first hop is first
    chronological_headers = list(reversed(received_headers))
    hops: List[ReceivedHop] = []
    previous_dt: Optional[datetime] = None

    for index, header_str in enumerate(chronological_headers, start=1):
        clean_header = " ".join(header_str.split())
        
        # 1. Extract from and by hosts
        from_match = FROM_REGEX.search(clean_header)
        by_match = BY_REGEX.search(clean_header)
        
        from_host = from_match.group(1).strip() if from_match else None
        by_host = by_match.group(1).strip() if by_match else None

        # 2. Extract IP address
        ip_addr = None
        # Look for [ip.add.re.ss] first
        bracket_ip = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", clean_header)
        if bracket_ip:
            ip_addr = bracket_ip.group(1)
        else:
            raw_ip = re.search(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", clean_header)
            if raw_ip:
                ip_addr = raw_ip.group(1)

        # 3. Extract Timestamp (usually after the last semicolon ';')
        dt = None
        delay_sec = 0
        anomalous = False
        anomaly_reason = None
        timestamp_str = None

        if ";" in clean_header:
            raw_date = clean_header.rsplit(";", 1)[-1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(raw_date)
                timestamp_str = dt.isoformat()
            except Exception:
                timestamp_str = raw_date

        # 4. Calculate delay delta
        if dt and previous_dt:
            try:
                delta = int((dt - previous_dt).total_seconds())
                delay_sec = max(0, delta)
                
                # Check for clock skew / forged timestamp
                if delta < -60:
                    anomalous = True
                    anomaly_reason = f"Clock Skew / Forged Header: Timestamp jumped {abs(delta)}s backwards"
                # Check for excessive delay
                elif delta > 3600:
                    anomalous = True
                    anomaly_reason = f"Unusual Latency: Mail was held or delayed for {delta // 60} minutes"
            except Exception:
                delay_sec = 0

        if dt:
            previous_dt = dt

        hops.append(ReceivedHop(
            hop_number=index,
            from_host=from_host,
            by_host=by_host,
            ip=ip_addr,
            timestamp=timestamp_str,
            delay_seconds=delay_sec,
            anomalous=anomalous,
            anomaly_reason=anomaly_reason
        ))

    return hops
