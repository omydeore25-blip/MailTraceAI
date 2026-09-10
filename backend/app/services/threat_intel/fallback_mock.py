import json
import os
from typing import Dict, Any, Optional
from app.core.logging import logger
from app.services.threat_intel.base import BaseThreatIntelProvider

MOCK_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "mock_ti_database.json")


class MockThreatIntelProvider(BaseThreatIntelProvider):
    """Offline deterministic mock threat intelligence engine."""

    def __init__(self):
        self.db = {"ips": {}, "domains": {}, "hashes": {}}
        self._load_db()

    def _load_db(self):
        try:
            if os.path.exists(MOCK_DB_PATH):
                with open(MOCK_DB_PATH, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load mock TI database ({e}), using default fallback logic")

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "provider": "InternalRouting",
                    "source": "rfc1918_internal",
                    "is_fallback": False,
                    "ioc_type": "ip",
                    "reputation_score": 0.0,
                    "is_malicious": False,
                    "abuse_confidence": 0,
                    "country": "LAN",
                    "city": "Internal / Private Subnet",
                    "latitude": None,
                    "longitude": None,
                    "isp": "Internal Network Hop",
                    "is_private": True,
                    "tags": ["RFC 1918 Private IP"]
                }
        except Exception:
            pass

        ip_entry = self.db.get("ips", {}).get(ip)

        if ip_entry:
            return {
                "provider": "MockThreatIntel",
                "source": "offline_demo_fallback",
                "is_fallback": True,
                "warning": "Demo/offline fallback data — real API key not configured",
                "ioc_type": "ip",
                "reputation_score": ip_entry.get("reputation_score", 0.0),
                "is_malicious": ip_entry.get("is_malicious", False),
                "abuse_confidence": ip_entry.get("abuse_confidence", 0),
                "country": ip_entry.get("country", "US"),
                "city": ip_entry.get("city", "Unknown"),
                "latitude": ip_entry.get("latitude", 0.0),
                "longitude": ip_entry.get("longitude", 0.0),
                "isp": ip_entry.get("isp", "Mock ISP"),
                "tags": ip_entry.get("tags", [])
            }
        
        # Generic heuristic score for unlisted IP
        return {
            "provider": "MockThreatIntel",
            "source": "offline_demo_fallback",
            "is_fallback": True,
            "warning": "Demo/offline fallback data — real API key not configured",
            "ioc_type": "ip",
            "reputation_score": 0.0,
            "is_malicious": False,
            "abuse_confidence": 0,
            "country": "US",
            "city": "Unknown",
            "latitude": 38.0,
            "longitude": -97.0,
            "isp": "Standard Cloud Provider",
            "tags": ["Clean / Unreported"]
        }

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        clean_d = domain.lower().strip()
        dom_entry = self.db.get("domains", {}).get(clean_d)
        if dom_entry:
            return {
                "provider": "MockThreatIntel",
                "source": "offline_demo_fallback",
                "is_fallback": True,
                "warning": "Demo/offline fallback data — real API key not configured",
                "ioc_type": "domain",
                "reputation_score": dom_entry.get("reputation_score", 0.0),
                "is_malicious": dom_entry.get("is_malicious", False),
                "categories": dom_entry.get("categories", []),
                "vt_positives": dom_entry.get("vt_positives", 0),
                "total": dom_entry.get("vt_total", 88),
                "registrar": dom_entry.get("registrar", "Unknown Registrar")
            }

        # Heuristic check
        is_suspicious = any(clean_d.endswith(ext) for ext in [".xyz", ".top", ".buzz", ".icu", ".click"]) or "login" in clean_d or "verify" in clean_d
        score = 65.0 if is_suspicious else 0.0
        return {
            "provider": "MockThreatIntel",
            "source": "offline_demo_fallback",
            "is_fallback": True,
            "warning": "Demo/offline fallback data — real API key not configured",
            "ioc_type": "domain",
            "reputation_score": score,
            "is_malicious": is_suspicious,
            "categories": ["Suspicious Keywords / TLD"] if is_suspicious else ["General Web"],
            "vt_positives": 8 if is_suspicious else 0,
            "total": 85,
            "registrar": "Privacy Guardian Inc." if is_suspicious else "Standard Registrar"
        }

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        lower_url = url.lower()
        is_mal = any(term in lower_url for term in [
            "password-reset", "verify-account", "update-payment", "secure-login",
            "micros0ft", "bank-secure", "authorize", "giftcard", "wire-transfer"
        ])
        score = 88.0 if is_mal else 0.0
        return {
            "provider": "MockThreatIntel",
            "source": "offline_demo_fallback",
            "is_fallback": True,
            "warning": "Demo/offline fallback data — real API key not configured",
            "ioc_type": "url",
            "reputation_score": score,
            "is_malicious": is_mal,
            "positives": 24 if is_mal else 0,
            "total": 88,
            "categories": ["Phishing / Credential Harvest"] if is_mal else ["Legitimate Link"]
        }

    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        clean_h = file_hash.lower().strip()
        h_entry = self.db.get("hashes", {}).get(clean_h)
        if h_entry:
            return {
                "provider": "MockThreatIntel",
                "source": "offline_demo_fallback",
                "is_fallback": True,
                "warning": "Demo/offline fallback data — real API key not configured",
                "ioc_type": "hash",
                "reputation_score": h_entry.get("reputation_score", 0.0),
                "is_malicious": h_entry.get("is_malicious", False),
                "threat_name": h_entry.get("threat_name", "Clean / Known Good"),
                "positives": h_entry.get("vt_positives", 0),
                "total": h_entry.get("vt_total", 72)
            }

        return {
            "provider": "MockThreatIntel",
            "source": "offline_demo_fallback",
            "is_fallback": True,
            "warning": "Demo/offline fallback data — real API key not configured",
            "ioc_type": "hash",
            "reputation_score": 0.0,
            "is_malicious": False,
            "threat_name": "No detection found",
            "positives": 0,
            "total": 70
        }
