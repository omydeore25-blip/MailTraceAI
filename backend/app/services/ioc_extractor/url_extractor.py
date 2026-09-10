import re
import html
import urllib.parse
from typing import List, Set, Tuple
from app.schemas.ioc import IOCItem

URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
)

HREF_REGEX = re.compile(r'href=[\'"]([^\'">]+)[\'"]', re.IGNORECASE)


def defang_url(url: str) -> str:
    """Defang URL for safe forensic display: hxxp[://]example[.]com."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang periods in domain
    return defanged.replace(".", "[.]")


def extract_urls(plain_body: str, html_body: str) -> List[IOCItem]:
    """Extract, deduplicate, and normalize all URLs from email content."""
    raw_urls: Set[str] = set()

    # 1. Plaintext body regex
    if plain_body:
        for match in URL_REGEX.finditer(plain_body):
            raw_urls.add(match.group(1).strip())

    # 2. HTML href and text
    if html_body:
        for match in HREF_REGEX.finditer(html_body):
            raw_urls.add(match.group(1).strip())
        for match in URL_REGEX.finditer(html_body):
            raw_urls.add(match.group(1).strip())

    items: List[IOCItem] = []
    seen: Set[str] = set()

    for raw_u in raw_urls:
        u = html.unescape(raw_u).strip()
        # Clean trailing punctuation
        u = re.sub(r"[.,;:!>)]+$", "", u)
        
        if not u or u.startswith("mailto:") or u.startswith("tel:") or u.startswith("#"):
            continue
        
        # Ensure scheme
        if not u.startswith("http://") and not u.startswith("https://") and not u.startswith("ftp://"):
            u = "http://" + u

        if u in seen:
            continue
        seen.add(u)

        items.append(IOCItem(
            ioc_type="url",
            value=u,
            defang_url=defang_url(u),
            defanged_value=defang_url(u),
            reputation_score=0.0,
            is_malicious=False,
            enrichment={}
        ))

    return items
