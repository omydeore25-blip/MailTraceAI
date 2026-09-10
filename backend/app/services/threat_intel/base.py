from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseThreatIntelProvider(ABC):
    """Abstract interface for threat intelligence enrichment providers."""

    @abstractmethod
    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query IP address reputation and geolocation."""
        pass

    @abstractmethod
    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query domain reputation and category."""
        pass

    @abstractmethod
    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query URL reputation and malicious scans."""
        pass

    @abstractmethod
    async def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query file hash (MD5, SHA1, SHA256) signature status."""
        pass
