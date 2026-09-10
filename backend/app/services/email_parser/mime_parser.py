"""
MIME Email Parser compatibility module.
Delegates directly to eml_parser to avoid duplicate logic.
"""
from typing import Dict, Any, Union
from app.services.email_parser.eml_parser import parse_raw_eml


def parse_raw_email(content: Union[str, bytes]) -> Dict[str, Any]:
    """
    Parse raw email string or bytes into structured forensic dictionary.
    Delegates to parse_raw_eml.
    """
    return parse_raw_eml(content)
