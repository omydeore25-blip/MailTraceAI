import os
import pytest
from app.api.v1.analysis import execute_forensic_pipeline

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "data", "samples")


def load_sample(filename: str) -> bytes:
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "rb") as f:
        return f.read()


@pytest.mark.asyncio
async def test_clean_newsletter_pipeline():
    content = load_sample("clean_newsletter.eml")
    result = await execute_forensic_pipeline(content, filename="clean_newsletter.eml")

    # 1. Clean email verification
    assert result.threat_level == "Clean"
    assert result.risk_score < 30.0

    # 2. Alerts verification: Clean email must not generate high or critical malicious alerts
    high_or_crit_alerts = [a for a in result.alerts if a.severity in ["High", "Critical"]]
    assert len(high_or_crit_alerts) == 0, f"Clean email generated unexpected high/critical alerts: {high_or_crit_alerts}"

    # 3. Hop & Geolocation verification
    assert len(result.hops) >= 2
    # Hop 1 is 10.0.1.5 (private IP)
    hop_private = next((h for h in result.hops if h.ip == "10.0.1.5"), None)
    assert hop_private is not None
    assert hop_private.is_private is True
    assert hop_private.latitude is None
    assert hop_private.longitude is None

    # Hop 2 is 198.51.100.25 (public IP)
    hop_public = next((h for h in result.hops if h.ip == "198.51.100.25"), None)
    assert hop_public is not None
    assert hop_public.is_private is False
    # If IPINFO_TOKEN is unconfigured, latitude and longitude must NOT be fabricated
    if hop_public.geo_status == "unconfigured":
        assert hop_public.latitude is None
        assert hop_public.longitude is None
        assert "IPinfo API key not configured" in (hop_public.geo_error or "")

    # 4. Graph verification
    assert result.graph is not None
    node_types = {n.type for n in result.graph.nodes}
    assert "email" in node_types
    assert "address" in node_types
    assert "domain" in node_types
    assert "ip" in node_types


@pytest.mark.asyncio
async def test_credential_phishing_pipeline():
    content = load_sample("credential_phishing.eml")
    result = await execute_forensic_pipeline(content, filename="credential_phishing.eml")

    # 1. Threat score
    assert result.threat_level in ["Malicious", "Critical"]
    assert result.risk_score >= 60.0

    # 2. Alerts generated
    alert_titles = [a.title.lower() for a in result.alerts]
    alert_severities = {a.severity for a in result.alerts}
    assert "critical" in [s.lower() for s in alert_severities] or "high" in [s.lower() for s in alert_severities]

    # Must detect phishing intent
    assert any("phish" in t for t in alert_titles)

    # Must detect authentication failures (SPF / DKIM / DMARC)
    assert any("spf" in t for t in alert_titles)
    assert any("dkim" in t for t in alert_titles)
    assert any("dmarc" in t for t in alert_titles)

    # Must detect spoofing
    assert any("spoof" in t for t in alert_titles)

    # 3. Graph verification
    assert result.graph is not None
    node_types = {n.type for n in result.graph.nodes}
    assert "url" in node_types or "address" in node_types
    edge_labels = {e.label for e in result.graph.edges}
    assert "SENT_BY" in edge_labels


@pytest.mark.asyncio
async def test_bec_wire_fraud_pipeline():
    content = load_sample("bec_wire_fraud.eml")
    result = await execute_forensic_pipeline(content, filename="bec_wire_fraud.eml")

    # 1. Threat evaluation
    assert result.threat_level in ["Suspicious", "Malicious", "Critical"]

    # 2. Alerts: BEC / wire fraud indicators
    alert_titles = [a.title.lower() for a in result.alerts]
    assert any("bec" in t or "wire" in t or "spoof" in t for t in alert_titles)

    # 3. Graph verification
    assert result.graph is not None
    assert len(result.graph.nodes) > 0


@pytest.mark.asyncio
async def test_dkim_spf_spoofed_pipeline():
    content = load_sample("dkim_spf_spoofed.eml")
    result = await execute_forensic_pipeline(content, filename="dkim_spf_spoofed.eml")

    # 1. Threat evaluation
    assert result.threat_level in ["Suspicious", "Malicious", "Critical"]

    # 2. Anomalous hop (clock skew)
    anomalous_hops = [h for h in result.hops if h.anomalous]
    assert len(anomalous_hops) > 0

    # 3. Alerts for spoofing and auth failure
    alert_titles = [a.title.lower() for a in result.alerts]
    assert any("anomalous" in t or "clock" in t or "spf" in t or "spoof" in t for t in alert_titles)

    # 4. Graph verification
    assert result.graph is not None
