"""
Hop Analyzer compatibility module.
Delegates to hop_timeline.parse_received_hops.
"""
from typing import List
from app.schemas.forensic_headers import ReceivedHop
from app.services.email_parser.hop_timeline import parse_received_hops


def analyze_received_hops(received_headers: List[str]) -> List[ReceivedHop]:
    """
    Parse email 'Received' headers into chronological hops with delay and anomaly analysis.
    """
    return parse_received_hops(received_headers)
