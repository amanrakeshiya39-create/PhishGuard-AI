"""
PhishGuard AI - Explainability Engine
Translates mathematical feature vectors and model probabilities into
human-interpretable cybersecurity explanations and diagnostic risk factors.
"""

from typing import Dict, Any, List


def generate_explanation(features: Dict[str, Any], risk_score: int, domain: str) -> Dict[str, Any]:
    """
    Evaluates individual feature anomalies and generates contextual risk factors
    with severity ratings and actionable explanations.
    """
    risk_factors: List[Dict[str, str]] = []

    # 1. Direct IP Hostname Check
    if features.get("has_ip", 0) == 1:
        risk_factors.append({
            "factor": "IP Address Used as Host",
            "severity": "HIGH",
            "description": f"The host '{domain}' is a raw IP address instead of a standard domain name, a tactic widely used to bypass domain reputation blocklists."
        })

    # 2. Suspicious TLD
    if features.get("has_suspicious_tld", 0) == 1:
        tld = domain.split(".")[-1] if "." in domain else ""
        risk_factors.append({
            "factor": f"High-Risk TLD (.{tld})",
            "severity": "HIGH",
            "description": f"The top-level domain '.{tld}' is frequently associated with disposable infrastructure and spam/phishing campaigns."
        })

    # 3. Suspicious Keywords
    keyword_count = features.get("has_suspicious_keywords", 0)
    if keyword_count > 0:
        severity = "HIGH" if keyword_count >= 2 else "MEDIUM"
        risk_factors.append({
            "factor": "Security / Credential Keywords",
            "severity": severity,
            "description": f"Contains {keyword_count} sensitive keyword(s) commonly used in credential harvesting lures (e.g. login, verify, secure, account)."
        })

    # 4. Punycode / Homograph Attack
    if features.get("is_punycode", 0) == 1:
        risk_factors.append({
            "factor": "Punycode (IDN Homograph) Detected",
            "severity": "HIGH",
            "description": "Domain utilizes internationalized Punycode ('xn--'), which can mimic well-known brand names using visual character substitution."
        })

    # 5. Excessive Subdomain Hierarchy
    subdomains = features.get("count_subdomains", 0)
    if subdomains >= 3:
        risk_factors.append({
            "factor": f"Deep Subdomain Nesting ({subdomains} levels)",
            "severity": "HIGH",
            "description": "An unusually deep subdomain structure was detected, often used to camouflage the real landing domain behind trusted brand names."
        })
    elif subdomains == 2:
        risk_factors.append({
            "factor": "Multiple Subdomains (2 levels)",
            "severity": "MEDIUM",
            "description": "Contains 2 subdomain levels. Common in both legitimate complex infrastructures and targeted phishing."
        })

    # 6. Double Slash Redirection
    if features.get("has_double_slash_redirect", 0) == 1:
        risk_factors.append({
            "factor": "Embedded Redirection Token ('//')",
            "severity": "HIGH",
            "description": "URL contains '//' after the protocol, which can trigger automatic client redirection to an external malicious server."
        })

    # 7. Non-standard Port
    if features.get("has_non_standard_port", 0) == 1:
        risk_factors.append({
            "factor": "Non-Standard Port Specified",
            "severity": "MEDIUM",
            "description": "The destination URL communicates over a non-standard web port (not 80 or 443), commonly observed on temporary rogue hosting."
        })

    # 8. Excessive Hyphenation
    hyphens = features.get("count_hyphens", 0)
    if hyphens >= 3:
        risk_factors.append({
            "factor": f"Excessive Hyphens ({hyphens} occurrences)",
            "severity": "MEDIUM",
            "description": "Multiple hyphens are commonly used by threat actors in domain squatting (e.g., 'service-update-verify-account')."
        })

    # 9. Insecure Protocol
    if features.get("has_https", 1) == 0:
        risk_factors.append({
            "factor": "Unencrypted Protocol (HTTP)",
            "severity": "MEDIUM",
            "description": "URL does not use HTTPS. Any submitted information or passwords can be intercepted in cleartext via man-in-the-middle attacks."
        })

    # 10. URL Shortener Abuse
    if features.get("is_shortened", 0) == 1:
        risk_factors.append({
            "factor": "URL Shortening Service",
            "severity": "LOW",
            "description": "The link uses a URL shortener, which masks the true target destination until clicked."
        })

    # 11. High Shannon Entropy
    entropy = features.get("url_entropy", 0.0)
    if entropy >= 4.6:
        risk_factors.append({
            "factor": f"High Character Randomness / Entropy ({entropy:.2f})",
            "severity": "LOW",
            "description": "URL exhibits high character randomness, which may indicate domain generation algorithms (DGA) or randomized obfuscation."
        })

    # Synthesize human-readable summary
    if risk_score >= 70:
        summary = (
            f"High risk URL exhibiting {len(risk_factors)} critical threat indicator(s). "
            "Strong evidence of deceptive domain structure or brand impersonation."
        )
    elif risk_score >= 35:
        summary = (
            f"Moderate risk URL with {len(risk_factors)} suspicious indicator(s). "
            "Certain lexical or structural patterns warrant manual review."
        )
    else:
        if not risk_factors:
            summary = "URL conforms to standard structural patterns with no significant anomalous markers detected."
        else:
            summary = f"URL exhibits minor structural traits ({len(risk_factors)} low-impact note(s)), but overall patterns align closely with legitimate profiles."

    return {
        "summary": summary,
        "risk_factors": risk_factors
    }
