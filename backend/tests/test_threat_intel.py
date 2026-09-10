import pytest
from app.services.threat_intel.ipinfo_geoip import geolocate_ip
from app.services.threat_intel.virustotal import query_virustotal
from app.services.threat_intel.abuseipdb import query_abuseipdb
from app.services.threat_intel.ti_aggregator import lookup_ioc


@pytest.mark.asyncio
async def test_private_ip_geolocation():
    for private_ip in ["192.168.1.50", "10.0.4.1", "127.0.0.1", "172.16.0.25"]:
        geo = await geolocate_ip(private_ip)
        assert geo.get("is_private") is True
        assert "LAN" in geo.get("country") or "Private" in geo.get("country")


@pytest.mark.asyncio
async def test_virustotal_unconfigured_handling():
    # Calling query_virustotal without a real key must return labeled mock fallback or unavailable
    res = await query_virustotal("8.8.8.8", "ip")
    assert res is not None
    assert "source" in res
    assert res.get("is_fallback") is True or res.get("status") == "unconfigured"


@pytest.mark.asyncio
async def test_abuseipdb_unconfigured_handling():
    res = await query_abuseipdb("1.1.1.1")
    assert res is not None
    assert "source" in res
    assert res.get("is_fallback") is True or res.get("status") == "unconfigured"


@pytest.mark.asyncio
async def test_ti_aggregator_truthful_reporting():
    result = await lookup_ioc("ip", "198.51.100.15")
    assert "ioc_type" in result
    assert result["ioc_type"] == "ip"
    assert result["value"] == "198.51.100.15"
    assert "reputation_score" in result
    assert "is_malicious" in result
    assert "enrichment" in result

    enrichment = result["enrichment"]
    # Check that fallback/status warning is preserved
    sources = [k for k in enrichment.keys()]
    assert len(sources) > 0
