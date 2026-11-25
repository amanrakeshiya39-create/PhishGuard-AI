"""
PhishGuard AI - Comprehensive Threat & Risk Catalog
Defines all phishing, structural, network, and availability threats detected by
the engine along with descriptions, examples, mitigations, and live scan counts.
"""

from typing import Any, Dict, List

THREAT_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "ip_as_host",
        "name": "Raw IP Address Used as Host",
        "category": "Network",
        "severity": "HIGH",
        "feature_key": "has_ip",
        "factor_match": "IP Address Used as Host",
        "description": (
            "The URL points directly to a raw IPv4 or IPv6 address instead of a registered "
            "domain name. Attackers use raw IPs to evade domain-reputation filters and host "
            "disposable credential-harvesting pages on compromised servers."
        ),
        "example": "http://192.168.1.1:8080/bank/login",
        "mitigation": "Never enter banking or account credentials on a bare IP address URL.",
    },
    {
        "id": "high_risk_tld",
        "name": "High-Risk / Disposable Top-Level Domain (TLD)",
        "category": "Domain",
        "severity": "HIGH",
        "feature_key": "has_suspicious_tld",
        "factor_match": "High-Risk TLD",
        "description": (
            "Extensions such as .xyz, .top, .tk, .ml, .ga, .cf, .gq, .buzz, and .icu have "
            "very low registration cost and weak abuse enforcement, making them heavily "
            "overrepresented in phishing and spam campaigns."
        ),
        "example": "http://paypal-security-verification.xyz/login.php",
        "mitigation": "Verify the organization's official domain extension (e.g., .com, .org, .gov) before trusting the link.",
    },
    {
        "id": "credential_keywords",
        "name": "Security & Credential Harvesting Keywords",
        "category": "Content & Lure",
        "severity": "HIGH",
        "feature_key": "has_suspicious_keywords",
        "factor_match": "Security / Credential Keywords",
        "description": (
            "Phishing URLs frequently embed urgent or trusted brand/action tokens such as "
            "'login', 'verify', 'security', 'update', 'suspended', 'paypal', or 'banking' "
            "in the hostname or path to create false legitimacy and panic."
        ),
        "example": "http://secure-account-verify-paypal.net/signin",
        "mitigation": "Navigate directly to the official service via a bookmark instead of clicking urgent verification links.",
    },
    {
        "id": "punycode_homograph",
        "name": "Punycode (IDN Homograph) Spoofing",
        "category": "Obfuscation",
        "severity": "HIGH",
        "feature_key": "is_punycode",
        "factor_match": "Punycode (IDN Homograph) Detected",
        "description": (
            "Internationalized domain names encoded with 'xn--' can substitute lookalike "
            "Unicode characters (e.g., Cyrillic letters) for Latin characters to impersonate "
            "well-known brands visually."
        ),
        "example": "https://xn--pypal-4ve.com/login",
        "mitigation": "Inspect the raw ASCII Punycode domain carefully and confirm via an official app or bookmark.",
    },
    {
        "id": "double_slash_redirect",
        "name": "Embedded Double-Slash Redirection ('//')",
        "category": "Obfuscation",
        "severity": "HIGH",
        "feature_key": "has_double_slash_redirect",
        "factor_match": "Embedded Redirection Token ('//')",
        "description": (
            "A '//' sequence appearing inside the URL path after the protocol often signals "
            "an open-redirect parameter or client-side redirection trick designed to bounce "
            "victims from a benign-looking prefix to an attacker-controlled site."
        ),
        "example": "https://trusted-portal.com/redirect//evil-phish.xyz",
        "mitigation": "Examine the full URL path and query parameters for embedded external URLs before clicking.",
    },
    {
        "id": "at_symbol_spoofing",
        "name": "Basic Auth '@' Credential Spoofing",
        "category": "Obfuscation",
        "severity": "HIGH",
        "feature_key": "has_at_symbol",
        "factor_match": "Credential '@' Symbol Spoofing",
        "description": (
            "Per RFC 3986 URI syntax, text before '@' in the authority section is treated as "
            "userinfo and ignored for routing, causing browsers to navigate to the domain "
            "after '@' while tricking users who only read the beginning of the link."
        ),
        "example": "http://paypal.com@attacker-portal.net/auth",
        "mitigation": "Always verify the actual hostname immediately preceding the first '/' after '@'.",
    },
    {
        "id": "deep_subdomain_nesting",
        "name": "Deep Subdomain Nesting",
        "category": "Domain",
        "severity": "HIGH",
        "feature_key": "subdomain_count",
        "factor_match": "Subdomain",
        "description": (
            "Chaining multiple subdomains (3+ levels) places familiar brand or security words "
            "at the left of the URL while hiding the true registered root domain at the far right."
        ),
        "example": "https://login.secure.account.bank.evil-domain.com/auth",
        "mitigation": "Read domains right-to-left: the two labels just before the first '/' identify the real owner.",
    },
    {
        "id": "unencrypted_http",
        "name": "Unencrypted Transport (Plain HTTP)",
        "category": "Protocol",
        "severity": "MEDIUM",
        "feature_key": "has_https",
        "factor_match": "Unencrypted Protocol (HTTP)",
        "description": (
            "Links serving login or personal forms over plain HTTP transmit data in cleartext "
            "without TLS encryption or certificate identity verification, exposing traffic to "
            "interception and tampering."
        ),
        "example": "http://portal-update.net/login",
        "mitigation": "Do not submit passwords, OTPs, or payment details on any page lacking valid HTTPS.",
    },
    {
        "id": "non_standard_port",
        "name": "Non-Standard Web Port",
        "category": "Network",
        "severity": "MEDIUM",
        "feature_key": "has_non_standard_port",
        "factor_match": "Non-Standard Port Specified",
        "description": (
            "Explicitly targeting ports other than 80 or 443 (such as :8080, :8443, or :3000) "
            "is uncommon for public production websites and frequently indicates makeshift "
            "phishing servers or compromised hosts."
        ),
        "example": "http://update-service.net:8080/signin",
        "mitigation": "Treat public links with unusual port numbers as untrusted unless inside a known internal network.",
    },
    {
        "id": "excessive_hyphens",
        "name": "Excessive Hyphenation / Brand Squatting",
        "category": "Domain",
        "severity": "MEDIUM",
        "feature_key": "count_hyphens",
        "factor_match": "Excessive Hyphens",
        "description": (
            "Domains containing 3 or more hyphens are commonly crafted to mimic official "
            "support portals (e.g., 'microsoft-account-recovery-help.com') when legitimate "
            "brand domains are already registered."
        ),
        "example": "http://paypal-security-update-verify.com/account",
        "mitigation": "Check for hyphenated lookalike domains and verify spelling against known official domains.",
    },
    {
        "id": "url_non_existent",
        "name": "Non-Existent or Inactive URL / Domain",
        "category": "Availability",
        "severity": "MEDIUM",
        "feature_key": "url_existence",
        "factor_match": "Unregistered or Inactive Domain",
        "description": (
            "Live DNS or HTTP verification indicates the domain does not resolve (NXDOMAIN) "
            "or the target endpoint returns HTTP 404/410. Phishing infrastructure is frequently "
            "taken down quickly after campaigns or fabricated in lures."
        ),
        "example": "http://nonexistent-bank-login-999.xyz/verify",
        "mitigation": "Verify whether the domain is legitimately active before trusting messages referencing it.",
    },
    {
        "id": "url_shortener",
        "name": "URL Shortener Obfuscation",
        "category": "Obfuscation",
        "severity": "LOW",
        "feature_key": "is_shortened",
        "factor_match": "URL Shortening Service",
        "description": (
            "Public link shorteners (bit.ly, tinyurl.com, t.co, rb.gy, etc.) conceal the "
            "final destination domain until the browser follows the redirect, which attackers "
            "exploit to bypass casual link inspection."
        ),
        "example": "https://bit.ly/3xY9zqA",
        "mitigation": "Preview or expand shortened links before opening them if the sender is unexpected.",
    },
    {
        "id": "high_entropy_dga",
        "name": "High Shannon Entropy / Random DGA Strings",
        "category": "Obfuscation",
        "severity": "LOW",
        "feature_key": "url_entropy",
        "factor_match": "High Character Randomness / Entropy",
        "description": (
            "High character randomness (Shannon entropy >= 4.6) suggests algorithmically "
            "generated domains (DGA), randomized disposable subdomains, or obfuscated "
            "tracking/credential tokens."
        ),
        "example": "https://a8b9c1d2e3f4g5h6x9z.top/auth?t=9f8a7c6b",
        "mitigation": "Legitimate user-facing portals rarely rely on random gibberish domain names.",
    },
]


def build_threats_catalog_response(all_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combines the static threat catalog with live observed trigger counts from scan history.
    """
    factor_tallies: Dict[str, int] = {}
    for scan in all_scans:
        explanation = scan.get("explanation") or {}
        for rf in explanation.get("risk_factors", []):
            fname = rf.get("factor", "")
            factor_tallies[fname] = factor_tallies.get(fname, 0) + 1

    enriched_threats: List[Dict[str, Any]] = []
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for entry in THREAT_CATALOG:
        sev = entry["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        match_prefix = entry["factor_match"]
        observed_count = sum(
            count for fname, count in factor_tallies.items()
            if match_prefix in fname
        )

        item = dict(entry)
        item["detected_count"] = observed_count
        enriched_threats.append(item)

    return {
        "total_threats": len(enriched_threats),
        "severity_breakdown": severity_counts,
        "total_scans_analyzed": len(all_scans),
        "threats": enriched_threats,
    }
