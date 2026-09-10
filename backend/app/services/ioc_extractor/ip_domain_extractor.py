import ipaddress
import re
import urllib.parse
from typing import List, Set, Tuple
from app.schemas.ioc import IOCItem

IP_REGEX = re.compile(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b")
DOMAIN_REGEX = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b")


def is_public_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is globally routable (not private/reserved/loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def defang_ip(ip_str: str) -> str:
    """Defang IP address: 1[.]2[.]3[.]4"""
    return ip_str.replace(".", "[.]")


def defang_domain(domain_str: str) -> str:
    """Defang domain: example[.]com"""
    return domain_str.replace(".", "[.]")


def extract_ips(text: str, hop_ips: List[str] = None) -> List[IOCItem]:
    """Extract public IPv4 addresses from text and transit hops."""
    found: Set[str] = set()
    
    if hop_ips:
        for ip in hop_ips:
            if ip and is_public_ip(ip):
                found.add(ip)

    if text:
        for match in IP_REGEX.finditer(text):
            ip = match.group(1)
            if is_public_ip(ip):
                found.add(ip)

    items: List[IOCItem] = []
    for ip in sorted(list(found)):
        items.append(IOCItem(
            ioc_type="ip",
            value=ip,
            defanged_value=defang_ip(ip),
            reputation_score=0.0,
            is_malicious=False,
            enrichment={}
        ))
    return items


def extract_domains(urls: List[str], text: str = "") -> List[IOCItem]:
    """Extract unique root and subdomains from URLs and text."""
    domains: Set[str] = set()

    for u in urls:
        try:
            parsed = urllib.parse.urlparse(u)
            netloc = parsed.netloc.split(":")[0].lower().strip()
            if netloc and "." in netloc and not is_public_ip(netloc):
                domains.add(netloc)
        except Exception:
            pass

    if text:
        for match in DOMAIN_REGEX.finditer(text):
            dom = match.group(1).lower().strip()
            # Ignore common file extensions matching domain pattern
            if not dom.endswith((".png", ".jpg", ".gif", ".pdf", ".css", ".js", ".html")):
                domains.add(dom)

    items: List[IOCItem] = []
    for d in sorted(list(domains)):
        items.append(IOCItem(
            ioc_type="domain",
            value=d,
            defanged_value=defang_domain(d),
            reputation_score=0.0,
            is_malicious=False,
            enrichment={}
        ))
    return items
