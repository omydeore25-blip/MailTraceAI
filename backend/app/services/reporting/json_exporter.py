import json
from typing import Dict, Any


def export_forensic_json(analysis_data: Dict[str, Any]) -> str:
    """Format full analysis case file as normalized JSON for SIEM/SOAR ingestion."""
    return json.dumps(analysis_data, indent=2, default=str)
