import ipaddress
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logging import logger
from app.services.threat_intel.base import BaseThreatIntelProvider


RFC_1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to RFC 1918, loopback, or link-local private space."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return any(ip_obj in net for net in RFC_1918_NETWORKS)
    except ValueError:
        return False


def is_eligible_public_ip(ip_str: str) -> bool:
    """Validate that an IP string is a syntactically valid public IPv4/IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if any(ip_obj in net for net in RFC_1918_NETWORKS):
            return False
        return not (ip_obj.is_multicast or ip_obj.is_unspecified)
    except ValueError:
        return False


class IPInfoGeoClient(BaseThreatIntelProvider):
    """Client for IPinfo.io GeoIP and ASN lookup with strict public validation."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.IPINFO_TOKEN

    @property
    def is_configured(self) -> bool:
        return bool(self.token and len(self.token.strip()) >= 8)

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        ip = (ip or "").strip()
        if not ip:
            return None

        # 1. Check for RFC 1918 / Loopback / Private / Reserved IPs
        if is_private_or_reserved_ip(ip):
            return {
                "provider": "InternalRouting",
                "ioc_type": "ip",
                "country": "Private / Internal Network",
                "city": "Internal / Private Subnet",
                "region": "RFC 1918 / Local",
                "latitude": None,
                "longitude": None,
                "org": "Internal Network Hop",
                "isp": "Internal Infrastructure",
                "asn": None,
                "timezone": "UTC",
                "is_private": True,
                "geo_status": "private",
                "error_message": None,
            }

        # 2. Validate syntactically
        if not is_eligible_public_ip(ip):
            return {
                "provider": "InvalidIP",
                "ioc_type": "ip",
                "country": None,
                "city": None,
                "region": None,
                "latitude": None,
                "longitude": None,
                "org": None,
                "isp": None,
                "asn": None,
                "is_private": False,
                "geo_status": "invalid",
                "error_message": f"Invalid IP address format: {ip}",
            }

        # 3. Eligible Public IP: Live query if configured
        if self.is_configured:
            try:
                url = f"https://ipinfo.io/{ip}/json?token={self.token}"
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        loc = data.get("loc", "").split(",")
                        lat = float(loc[0]) if len(loc) == 2 else None
                        lon = float(loc[1]) if len(loc) == 2 else None
                        org_raw = data.get("org", "")
                        asn = None
                        isp = org_raw
                        if org_raw and org_raw.startswith("AS"):
                            parts = org_raw.split(" ", 1)
                            asn = parts[0]
                            isp = parts[1] if len(parts) > 1 else org_raw

                        return {
                            "provider": "IPinfo",
                            "ioc_type": "ip",
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "region": data.get("region"),
                            "latitude": lat,
                            "longitude": lon,
                            "org": org_raw or None,
                            "isp": isp or None,
                            "asn": asn,
                            "timezone": data.get("timezone", "UTC"),
                            "is_private": False,
                            "geo_status": "available",
                            "error_message": None,
                        }
                    else:
                        logger.warning(f"IPinfo returned HTTP {resp.status_code} for {ip}")
                        return {
                            "provider": "IPinfo",
                            "ioc_type": "ip",
                            "country": None,
                            "city": None,
                            "region": None,
                            "latitude": None,
                            "longitude": None,
                            "org": None,
                            "isp": None,
                            "asn": None,
                            "is_private": False,
                            "geo_status": "error",
                            "error_message": f"GeoLocation unavailable — IPinfo HTTP error {resp.status_code}",
                        }
            except Exception as e:
                logger.warning(f"IPinfo query failed for {ip}: {e}")
                return {
                    "provider": "IPinfo",
                    "ioc_type": "ip",
                    "country": None,
                    "city": None,
                    "region": None,
                    "latitude": None,
                    "longitude": None,
                    "org": None,
                    "isp": None,
                    "asn": None,
                    "is_private": False,
                    "geo_status": "error",
                    "error_message": f"GeoLocation unavailable — {str(e)}",
                }

        # 4. Truthful reporting: Never fabricate geographic information
        return {
            "provider": "IPinfo",
            "ioc_type": "ip",
            "country": None,
            "city": None,
            "region": None,
            "latitude": None,
            "longitude": None,
            "org": None,
            "isp": None,
            "asn": None,
            "is_private": False,
            "geo_status": "unconfigured",
            "error_message": "GeoLocation unavailable — IPinfo API key not configured",
        }

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return None

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        return None

    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return None


# Module-level client instance and exported geolocate_ip function
_ipinfo_client = IPInfoGeoClient()


async def geolocate_ip(ip: str) -> Dict[str, Any]:
    """
    Geolocate an IP address using IPinfo with private-IP detection.
    Never fabricates geographic information.
    """
    res = await _ipinfo_client.check_ip(ip)
    return res or {}
