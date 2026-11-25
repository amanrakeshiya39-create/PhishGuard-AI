"""
PhishGuard AI - URL Authenticity Verdict Service (Real vs. Fake)
Combines ML risk scoring, brand-impersonation/typosquatting heuristics, and live
reachability signals to produce a clear Real / Suspicious / Fake assessment.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

# Official root domains for commonly impersonated brands
OFFICIAL_BRAND_DOMAINS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "google.co.uk", "googleapis.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "github": {"github.com", "githubusercontent.com"},
}

# Common leetspeak / typosquatting patterns mapped to target brand names
BRAND_TYPOSQUATS: Dict[str, str] = {
    "paypa1": "paypal",
    "paypai": "paypal",
    "peypal": "paypal",
    "g00gle": "google",
    "gooogle": "google",
    "goog1e": "google",
    "micros0ft": "microsoft",
    "mircosoft": "microsoft",
    "app1e": "apple",
    "arnazon": "amazon",
    "amaz0n": "amazon",
    "netf1ix": "netflix",
    "faceb00k": "facebook",
    "instagrarn": "instagram",
}


def _extract_root_domain(domain: str) -> str:
    """Extracts the registrable-style trailing two labels (e.g. 'sub.google.com' -> 'google.com')."""
    cleaned = (domain or "").lower().strip(".")
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) <= 2:
        return cleaned
    return ".".join(parts[-2:])


def _detect_brand_impersonation(domain: str) -> Optional[Tuple[str, str]]:
    """
    Returns (brand_name, reason) if the hostname contains or typosquats a known
    brand while not belonging to that brand's official root domain.
    """
    host = (domain or "").lower()
    if not host:
        return None

    root_domain = _extract_root_domain(host)

    for typo, brand in BRAND_TYPOSQUATS.items():
        if typo in host and root_domain not in OFFICIAL_BRAND_DOMAINS[brand]:
            return (
                brand,
                f"Hostname '{host}' contains lookalike typosquat '{typo}' impersonating '{brand}'.",
            )

    for brand, official_roots in OFFICIAL_BRAND_DOMAINS.items():
        if brand in host and root_domain not in official_roots:
            return (
                brand,
                f"Hostname '{host}' references '{brand}' on an unofficial domain ('{root_domain}').",
            )

    return None


def assess_url_authenticity(
    domain: str,
    normalized_url: str,
    features: Dict[str, Any],
    risk_score: int,
    classification: str,
    confidence: float,
    url_existence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Determines whether a URL is Likely Real, Suspicious, or Likely Fake (Phishing),
    returning structured verdict metadata and clear human-readable reasons.
    """
    reasons: List[str] = []
    impersonated_brand: Optional[str] = None

    brand_hit = _detect_brand_impersonation(domain)
    if brand_hit:
        impersonated_brand, brand_reason = brand_hit
        reasons.append(brand_reason)

    if features.get("has_ip") == 1:
        reasons.append("Uses a raw IP address instead of a verified domain name.")
    if features.get("is_punycode") == 1:
        reasons.append("Uses Punycode ('xn--') encoding which can visually mimic legitimate domains.")
    if features.get("has_at_symbol") == 1:
        reasons.append("Contains '@' in the URL authority section to mask the true destination host.")
    if features.get("has_suspicious_tld") == 1:
        tld = domain.split(".")[-1] if "." in domain else ""
        reasons.append(f"Registered under a high-abuse top-level domain (.{tld}).")
    if features.get("has_https") == 0:
        reasons.append("Lacks HTTPS encryption (unencrypted HTTP transport).")

    existence_note: Optional[str] = None
    page_not_found = False
    if url_existence:
        http_status = url_existence.get("http_status")
        dns_resolved = url_existence.get("dns_resolved", False)
        exists = url_existence.get("exists")
        if exists is True and http_status is not None:
            existence_note = f"Live server responded (HTTP {http_status})."
        elif dns_resolved and exists is False and http_status in (404, 410):
            page_not_found = True
            reasons.append(f"Domain resolved, but this specific URL returned HTTP {http_status} (page not found).")
        elif exists is False:
            reasons.append("Domain did not resolve during live DNS verification.")

    # Decision synthesis
    if risk_score >= 70 or classification == "Phishing" or impersonated_brand is not None:
        verdict = "Fake"
        label = "Likely Fake (Phishing)"
        tone = "fake"
        summary = (
            f"This URL is classified as likely fake/phishing (Risk Score: {risk_score}/100). "
            "Do not enter credentials or personal details."
        )
        if not reasons:
            reasons.append("Machine learning and structural heuristics strongly match phishing patterns.")
    elif risk_score >= 35 or classification == "Suspicious" or page_not_found:
        verdict = "Suspicious"
        label = "Suspicious (Could Be Fake)"
        tone = "suspicious"
        summary = (
            f"This URL shows suspicious traits or incomplete verification (Risk Score: {risk_score}/100). "
            "Verify the source independently before trusting it."
        )
        if not reasons:
            reasons.append("Moderate structural anomalies warrant manual verification.")
    else:
        verdict = "Real"
        label = "Likely Real"
        tone = "real"
        summary = (
            f"This URL aligns with legitimate website patterns (Risk Score: {risk_score}/100) "
            "with no brand impersonation or phishing indicators detected."
        )
        if existence_note:
            reasons.insert(0, existence_note)
        if not reasons:
            reasons.append("No deceptive domain, obfuscation, or credential-lure patterns detected.")

    return {
        "verdict": verdict,
        "label": label,
        "tone": tone,
        "confidence": round(float(confidence), 2),
        "brand_impersonation": impersonated_brand,
        "summary": summary,
        "reasons": reasons,
    }
