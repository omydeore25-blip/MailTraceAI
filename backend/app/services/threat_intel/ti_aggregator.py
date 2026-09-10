import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.threat_intel_cache import ThreatIntelCache
from app.services.threat_intel.virustotal import VirusTotalClient
from app.services.threat_intel.abuseipdb import AbuseIPDBClient
from app.services.threat_intel.ipinfo_geoip import IPInfoGeoClient
from app.services.threat_intel.fallback_mock import MockThreatIntelProvider
from app.core.logging import logger


class ThreatIntelAggregator:
    """Unified threat intelligence enrichment orchestrator with multi-provider failover and caching."""

    def __init__(self):
        self.vt = VirusTotalClient()
        self.abuse = AbuseIPDBClient()
        self.ipinfo = IPInfoGeoClient()
        self.mock = MockThreatIntelProvider()

    async def _get_from_cache(self, db: AsyncSession, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        try:
            now = datetime.now(timezone.utc)
            query = select(ThreatIntelCache).where(
                ThreatIntelCache.ioc_type == ioc_type,
                ThreatIntelCache.ioc_value == ioc_value,
                ThreatIntelCache.expires_at > now
            )
            result = await db.execute(query)
            entry = result.scalar_one_or_none()
            if entry:
                return entry.data
        except Exception as e:
            logger.warning(f"Error reading TI cache: {e}")
        return None

    async def _save_to_cache(self, db: AsyncSession, ioc_type: str, ioc_value: str, provider: str, score: float, data: Dict[str, Any]):
        try:
            now = datetime.now(timezone.utc)
            expires = now + timedelta(hours=24)
            cache_record = ThreatIntelCache(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                provider=provider,
                score=score,
                data=data,
                cached_at=now,
                expires_at=expires
            )
            db.add(cache_record)
            await db.commit()
        except Exception as e:
            logger.warning(f"Error writing to TI cache: {e}")
            await db.rollback()

    async def enrich_ip(self, ip: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Enrich IP with AbuseIPDB, VirusTotal, IPinfo, or Mock Fallback."""
        if db:
            cached = await self._get_from_cache(db, "ip", ip)
            if cached:
                return cached

        # Execute online queries
        abuse_res = await self.abuse.check_ip(ip) if self.abuse.is_configured else None
        vt_res = await self.vt.check_ip(ip) if self.vt.is_configured else None
        geo_res = await self.ipinfo.check_ip(ip)

        # Fallback if no real intel available
        if not abuse_res and not vt_res:
            mock_res = await self.mock.check_ip(ip)
            combined = {**(mock_res or {}), **(geo_res or {})}
            if geo_res and geo_res.get("is_private"):
                combined["is_private"] = True
                combined["country"] = geo_res.get("country", "LAN")
                combined["city"] = geo_res.get("city", "Internal / Private Subnet")
                combined["provider"] = "InternalRouting"
                combined["is_fallback"] = False
            elif not self.abuse.is_configured and not self.vt.is_configured:
                combined["provider_status"] = "Provider unavailable — VirusTotal and AbuseIPDB API keys not configured"
        else:
            combined = {**geo_res}

            if abuse_res:
                combined.update(abuse_res)
            if vt_res:
                combined["virustotal"] = vt_res
                # Maximize reputation score
                combined["reputation_score"] = max(combined.get("reputation_score", 0.0), vt_res.get("reputation_score", 0.0))
                combined["is_malicious"] = combined.get("is_malicious", False) or vt_res.get("is_malicious", False)
            combined["is_fallback"] = False

        if db:
            await self._save_to_cache(db, "ip", ip, combined.get("provider", "Aggregator"), combined.get("reputation_score", 0.0), combined)

        return combined

    async def enrich_domain(self, domain: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Enrich domain with VirusTotal or Mock Fallback."""
        clean_d = domain.lower().strip()
        if db:
            cached = await self._get_from_cache(db, "domain", clean_d)
            if cached:
                return cached

        vt_res = await self.vt.check_domain(clean_d) if self.vt.is_configured else None
        if not vt_res:
            vt_res = await self.mock.check_domain(clean_d)
            if not self.vt.is_configured and vt_res:
                vt_res["provider_status"] = "Provider unavailable — VirusTotal API key not configured"

        if db and vt_res:
            await self._save_to_cache(db, "domain", clean_d, vt_res.get("provider", "Aggregator"), vt_res.get("reputation_score", 0.0), vt_res)

        return vt_res or {}

    async def enrich_url(self, url: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Enrich URL with VirusTotal or Mock Fallback."""
        if db:
            cached = await self._get_from_cache(db, "url", url)
            if cached:
                return cached

        vt_res = await self.vt.check_url(url) if self.vt.is_configured else None
        if not vt_res:
            vt_res = await self.mock.check_url(url)
            if not self.vt.is_configured and vt_res:
                vt_res["provider_status"] = "Provider unavailable — VirusTotal API key not configured"

        if db and vt_res:
            await self._save_to_cache(db, "url", url, vt_res.get("provider", "Aggregator"), vt_res.get("reputation_score", 0.0), vt_res)

        return vt_res or {}

    async def enrich_hash(self, file_hash: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Enrich file hash with VirusTotal or Mock Fallback."""
        clean_h = file_hash.lower().strip()
        if db:
            cached = await self._get_from_cache(db, "hash", clean_h)
            if cached:
                return cached

        vt_res = await self.vt.check_hash(clean_h) if self.vt.is_configured else None
        if not vt_res:
            vt_res = await self.mock.check_hash(clean_h)
            if not self.vt.is_configured and vt_res:
                vt_res["provider_status"] = "Provider unavailable — VirusTotal API key not configured"

        if db and vt_res:
            await self._save_to_cache(db, "hash", clean_h, vt_res.get("provider", "Aggregator"), vt_res.get("reputation_score", 0.0), vt_res)

        return vt_res or {}


# Module-level instance and lookup_ioc helper function
threat_intel_aggregator = ThreatIntelAggregator()


async def lookup_ioc(ioc_type: str, value: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    """Lookup and enrich an IOC across configured providers or offline fallback."""
    ioc_type_clean = ioc_type.lower().strip()
    val = value.strip()

    if ioc_type_clean == "ip":
        enrichment = await threat_intel_aggregator.enrich_ip(val, db=db)
    elif ioc_type_clean == "domain":
        enrichment = await threat_intel_aggregator.enrich_domain(val, db=db)
    elif ioc_type_clean == "url":
        enrichment = await threat_intel_aggregator.enrich_url(val, db=db)
    elif ioc_type_clean in ["hash", "md5", "sha1", "sha256"]:
        enrichment = await threat_intel_aggregator.enrich_hash(val, db=db)
    else:
        enrichment = {"error": f"Unsupported IOC type: {ioc_type}"}

    return {
        "ioc_type": ioc_type_clean,
        "value": val,
        "reputation_score": enrichment.get("reputation_score", 0.0),
        "is_malicious": enrichment.get("is_malicious", False),
        "enrichment": enrichment
    }

