from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logging import logger
from app.services.threat_intel.base import BaseThreatIntelProvider


class AbuseIPDBClient(BaseThreatIntelProvider):
    """Client for AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "true"
            }
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(self.BASE_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    confidence = float(data.get("abuseConfidenceScore", 0))
                    return {
                        "provider": "AbuseIPDB",
                        "ioc_type": "ip",
                        "abuse_confidence": confidence,
                        "reputation_score": confidence,
                        "is_malicious": confidence >= 25.0,
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "usage_type": data.get("usageType"),
                        "total_reports": data.get("totalReports", 0),
                        "last_reported_at": data.get("lastReportedAt")
                    }
        except Exception as e:
            logger.warning(f"AbuseIPDB IP query failed: {e}")
        return None

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return None

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        return None

    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return None


# Module-level client and exported query_abuseipdb function
_abuse_client = AbuseIPDBClient()
_mock_provider = None


async def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB for IP reputation.
    If ABUSEIPDB_API_KEY is configured, performs live API query.
    Otherwise returns explicitly labeled offline fallback/unconfigured status.
    """
    if _abuse_client.is_configured:
        res = await _abuse_client.check_ip(ip)
        if res:
            res["source"] = "abuseipdb_api"
            res["is_fallback"] = False
            return res

    # Explicitly labeled offline demo fallback
    from app.services.threat_intel.fallback_mock import MockThreatIntelProvider
    global _mock_provider
    if _mock_provider is None:
        _mock_provider = MockThreatIntelProvider()

    mock_res = await _mock_provider.check_ip(ip)
    if mock_res:
        mock_res["source"] = "offline_demo_fallback"
        mock_res["is_fallback"] = True
        mock_res["warning"] = "Demo/offline fallback data — real ABUSEIPDB_API_KEY not configured"
        return mock_res

    return {
        "status": "unconfigured",
        "source": "offline_demo_fallback",
        "is_fallback": True,
        "warning": "Provider unavailable — ABUSEIPDB_API_KEY not configured",
        "provider": "AbuseIPDB"
    }

