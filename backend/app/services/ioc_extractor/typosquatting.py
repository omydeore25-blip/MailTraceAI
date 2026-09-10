from typing import Dict, Any, List, Optional, Tuple

HIGH_VALUE_DOMAINS = [
    "microsoft.com", "office.com", "office365.com", "live.com", "outlook.com",
    "google.com", "gmail.com", "apple.com", "icloud.com",
    "amazon.com", "paypal.com", "netflix.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
    "linkedin.com", "facebook.com", "instagram.com"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
    ".buzz", ".icu", ".cam", ".rest", ".link", ".bar", ".cfd", ".sbs"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_typosquatting(domain: str) -> Optional[Dict[str, Any]]:
    """
    Evaluate if a domain is a typosquatted / lookalike version of a legitimate high-profile brand.
    """
    clean_domain = domain.lower().strip()
    
    # Check suspicious TLD first
    has_suspicious_tld = any(clean_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # Normalize common character substitutions (homoglyph approximation)
    normalized = (clean_domain
                  .replace("0", "o")
                  .replace("1", "l")
                  .replace("rn", "m")
                  .replace("vv", "w")
                  .replace("-", ""))

    for legitimate in HIGH_VALUE_DOMAINS:
        legit_name = legitimate.split(".")[0]
        
        # Exact match is legitimate
        if clean_domain == legitimate or clean_domain.endswith("." + legitimate):
            return None

        # Check if brand name is embedded inside an attacker domain
        # e.g., 'microsoft-security-verify.com', 'paypal-login-portal.net'
        if legit_name in clean_domain:
            return {
                "flagged": True,
                "target_brand": legitimate,
                "technique": "Brand Substring Impersonation",
                "risk_score": 85.0,
                "reason": f"Domain '{domain}' embeds trusted brand '{legit_name}' to deceive recipients"
            }

        # Check Levenshtein distance on root name
        domain_name = clean_domain.split(".")[0]
        dist = levenshtein_distance(domain_name, legit_name)
        if 1 <= dist <= 2 and len(domain_name) >= 4:
            return {
                "flagged": True,
                "target_brand": legitimate,
                "technique": "Levenshtein Typosquatting",
                "risk_score": 90.0,
                "reason": f"Domain '{domain}' is visually similar to '{legitimate}' (Edit distance: {dist})"
            }

    if has_suspicious_tld:
        return {
            "flagged": True,
            "target_brand": "Generic Abuse",
            "technique": "High-Abuse TLD",
            "risk_score": 50.0,
            "reason": f"Domain '{domain}' utilizes a top-level domain frequently associated with spam and malware campaigns"
        }

    return None
