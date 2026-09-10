import pytest
from app.services.authentication.spf_verifier import verify_spf
from app.services.authentication.dkim_verifier import verify_dkim
from app.services.authentication.dmarc_verifier import verify_dmarc
from app.services.authentication.arc_verifier import verify_arc
from app.services.authentication import audit_authentication
from app.schemas.authentication import SPFResult, DKIMResult


def test_spf_verifier_with_auth_header():
    raw_headers = """Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of newsletter@techweekly.org designates 198.51.100.15 as permitted sender)
       smtp.mailfrom=newsletter@techweekly.org"""
    
    result = verify_spf(from_domain="techweekly.org", client_ip="198.51.100.15", raw_headers=raw_headers)
    assert result.status == "pass"
    assert result.aligned is True
    assert result.verification_method in ["inferred", "live_dns"]


def test_spf_verifier_softfail():
    raw_headers = """Authentication-Results: mx.example.com; spf=softfail (ip 203.0.113.50 is transitioning)"""
    result = verify_spf(from_domain="example.com", client_ip="203.0.113.50", raw_headers=raw_headers)
    assert result.status == "softfail"
    assert result.aligned is False


def test_dkim_verifier_with_auth_header():
    raw_headers = """Authentication-Results: mx.google.com;
       dkim=pass header.i=@techweekly.org header.s=s2026 header.b=AbCdEf
    DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=techweekly.org; s=s2026;
       bh=abcdef123456=; b=xyz987654="""

    result = verify_dkim(from_domain="techweekly.org", raw_headers=raw_headers)
    assert result.status == "pass"
    assert result.selector == "s2026"
    assert result.domain == "techweekly.org"
    assert result.aligned is True
    assert result.signature_found is True
    assert result.verification_method in ["inferred", "live_dns_crypto"]


def test_dmarc_verifier_aligned_pass():
    raw_headers = """Authentication-Results: mx.google.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE)"""
    spf_res = SPFResult(status="pass", aligned=True, evaluated_domain="techweekly.org")
    dkim_res = DKIMResult(status="pass", aligned=True, domain="techweekly.org")

    result = verify_dmarc(from_domain="techweekly.org", spf_result=spf_res, dkim_result=dkim_res, raw_headers=raw_headers)
    assert result.status == "pass"
    assert result.spf_aligned is True
    assert result.dkim_aligned is True


def test_dmarc_verifier_fail():
    raw_headers = """Authentication-Results: mx.google.com; dmarc=fail (p=REJECT)"""
    spf_res = SPFResult(status="fail", aligned=False, evaluated_domain="spoofed.com")
    dkim_res = DKIMResult(status="none", aligned=False, domain=None)

    result = verify_dmarc(from_domain="legitimate.com", spf_result=spf_res, dkim_result=dkim_res, raw_headers=raw_headers)
    assert result.status == "fail"
    assert result.spf_aligned is False
    assert result.dkim_aligned is False


def test_arc_verifier():
    raw_headers = """ARC-Seal: i=1; a=rsa-sha256; cv=none; d=google.com; s=arc2024; b=...
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc2024; b=..."""
    result = verify_arc(raw_headers=raw_headers)
    assert result.chain_validated is True
    assert result.status == "pass"


def test_audit_authentication_comprehensive():
    raw_headers = """Authentication-Results: mx.google.com;
       spf=pass;
       dkim=pass;
       dmarc=pass (p=REJECT)
    DKIM-Signature: v=1; a=rsa-sha256; d=techweekly.org; s=s1;"""

    summary = audit_authentication(
        from_domain="techweekly.org",
        client_ip="198.51.100.1",
        raw_headers=raw_headers
    )
    assert summary.overall_authenticated is True
    assert len(summary.failure_reasons) == 0
