import base64
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.core.logging import logger
from app.services.threat_intel.base import BaseThreatIntelProvider


class VirusTotalClient(BaseThreatIntelProvider):
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    def _headers(self) -> dict:
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.BASE_URL}/urls/{url_id}", headers=self._headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    score = min(100.0, (malicious * 25.0) + (suspicious * 10.0))
                    return {
                        "provider": "VirusTotal",
                        "ioc_type": "url",
                        "positives": malicious,
                        "total": total,
                        "reputation_score": score,
                        "is_malicious": malicious >= 2,
                        "categories": list(data.get("categories", {}).values())[:5]
                    }
        except Exception as e:
            logger.warning(f"VirusTotal URL query failed: {e}")
        return None

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.BASE_URL}/domains/{domain}", headers=self._headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    score = min(100.0, (malicious / max(1, total)) * 100.0 * 2.0)
                    return {
                        "provider": "VirusTotal",
                        "ioc_type": "domain",
                        "positives": malicious,
                        "total": total,
                        "reputation_score": score,
                        "is_malicious": malicious >= 2,
                        "registrar": data.get("registrar")
                    }
        except Exception as e:
            logger.warning(f"VirusTotal domain query failed: {e}")
        return None

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.BASE_URL}/ip_addresses/{ip}", headers=self._headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    score = min(100.0, malicious * 20.0)
                    return {
                        "provider": "VirusTotal",
                        "ioc_type": "ip",
                        "positives": malicious,
                        "total": sum(stats.values()),
                        "reputation_score": score,
                        "is_malicious": malicious >= 2,
                        "as_owner": data.get("as_owner")
                    }
        except Exception as e:
            logger.warning(f"VirusTotal IP query failed: {e}")
        return None

    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.BASE_URL}/files/{file_hash}", headers=self._headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    score = min(100.0, (malicious / max(1, total)) * 100.0)
                    return {
                        "provider": "VirusTotal",
                        "ioc_type": "hash",
                        "positives": malicious,
                        "total": total,
                        "reputation_score": score,
                        "is_malicious": malicious >= 2,
                        "meaningful_name": data.get("meaningful_name")
                    }
        except Exception as e:
            logger.warning(f"VirusTotal hash query failed: {e}")
        return None


# Module-level client and exported query_virustotal function
_vt_client = VirusTotalClient()
_mock_provider = None


async def query_virustotal(value: str, ioc_type: str = "ip") -> Dict[str, Any]:
    """
    Query VirusTotal for URL, domain, IP, or file hash.
    If VIRUSTOTAL_API_KEY is configured, queries live API.
    Otherwise returns explicitly labeled offline fallback/unconfigured status.
    """
    if _vt_client.is_configured:
        if ioc_type == "url":
            res = await _vt_client.check_url(value)
        elif ioc_type == "domain":
            res = await _vt_client.check_domain(value)
        elif ioc_type == "hash":
            res = await _vt_client.check_hash(value)
        else:
            res = await _vt_client.check_ip(value)
        if res:
            res["source"] = "virustotal_api"
            res["is_fallback"] = False
            return res

    # Explicitly labeled offline demo fallback
    from app.services.threat_intel.fallback_mock import MockThreatIntelProvider
    global _mock_provider
    if _mock_provider is None:
        _mock_provider = MockThreatIntelProvider()

    if ioc_type in ["url", "domain"]:
        mock_res = await _mock_provider.check_domain(value)
    elif ioc_type == "hash":
        mock_res = await _mock_provider.check_hash(value)
    else:
        mock_res = await _mock_provider.check_ip(value)

    if mock_res:
        mock_res["source"] = "offline_demo_fallback"
        mock_res["is_fallback"] = True
        mock_res["warning"] = "Demo/offline fallback data — real VIRUSTOTAL_API_KEY not configured"
        return mock_res

    return {
        "status": "unconfigured",
        "source": "offline_demo_fallback",
        "is_fallback": True,
        "warning": "Provider unavailable — VIRUSTOTAL_API_KEY not configured",
        "provider": "VirusTotal"
    }

