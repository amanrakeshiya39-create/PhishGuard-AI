"""
PhishGuard AI - URL Authenticity Verdict Service (Real vs. Fake)
Combines ML risk scoring, brand-impersonation/typosquatting heuristics, and live
reachability signals to produce a clear Real / Suspicious / Fake assessment.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Official domains for commonly impersonated brands
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

MULTI_PART_PUBLIC_SUFFIXES: Set[str] = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.in",
    "net.in",
    "org.in",
    "com.au",
    "net.au",
    "co.jp",
    "com.br",
}

DECEPTIVE_DOMAIN_WORDS: Set[str] = {"fake", "phish", "phishing", "scam", "fraud"}

ACTION_LURE_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "security",
    "secure",
    "confirm",
    "password",
    "credential",
    "authenticate",
    "auth",
    "banking",
    "bank",
    "wallet",
    "billing",
    "recovery",
    "suspended",
    "validate",
    "unlock",
    "kyc",
}


def _extract_root_domain(domain: str) -> str:
    """
    Extracts the registrable root domain, accounting for common 2-level public
    suffixes such as '.co.uk' or '.co.in'.
    """
    cleaned = (domain or "").lower().strip(".")
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) <= 2:
        return cleaned
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _is_official_brand_host(host: str, official_roots: Set[str]) -> bool:
    """Checks whether host matches or is a subdomain of an official brand domain."""
    return any(host == root or host.endswith("." + root) for root in official_roots)


def has_deceptive_host_words(domain: str) -> bool:
    """Checks whether the hostname contains explicit deceptive/mock threat words."""
    host = (domain or "").lower()
    return any(word in host for word in DECEPTIVE_DOMAIN_WORDS)


def detect_brand_impersonation(domain: str) -> Optional[Tuple[str, str]]:
    """
    Returns (brand_name, reason) if hostname tokens contain or typosquat a known
    brand while not belonging to that brand's official root domain.
    """
    host = (domain or "").lower().strip(".")
    if not host:
        return None

    root_domain = _extract_root_domain(host)
    tokens = [t for t in re.split(r"[.-]+", host) if t]

    for typo, brand in BRAND_TYPOSQUATS.items():
        if typo in tokens and not _is_official_brand_host(host, OFFICIAL_BRAND_DOMAINS[brand]):
            return (
                brand,
                f"Hostname '{host}' contains lookalike typosquat '{typo}' impersonating '{brand}'.",
            )

    for brand, official_roots in OFFICIAL_BRAND_DOMAINS.items():
        if brand in tokens and not _is_official_brand_host(host, official_roots):
            return (
                brand,
                f"Hostname '{host}' references '{brand}' on an unofficial domain ('{root_domain}').",
            )

    return None


def apply_authenticity_risk_guardrails(
    domain: str,
    normalized_url: str,
    features: Dict[str, Any],
    risk_score: int,
    url_existence: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Aligns the numeric 0-100 risk score with strong authenticity and existence
    signals so the Risk Gauge and Real/Fake Verdict never contradict each other.
    """
    score = int(risk_score)
    all_tokens = {t for t in re.split(r"[^a-z0-9-]+", (normalized_url or "").lower()) if t}
    has_lure = bool(all_tokens & ACTION_LURE_KEYWORDS)
    deceptive = has_deceptive_host_words(domain)
    brand_hit = detect_brand_impersonation(domain)

    if brand_hit is not None or features.get("has_at_symbol") == 1:
        score = max(score, 85)

    if features.get("has_suspicious_tld") == 1 and features.get("has_https") == 0:
        score = max(score, 72 if (has_lure or deceptive or features.get("count_hyphens", 0) >= 2) else 55)

    if features.get("is_shortened") == 1:
        score = max(score, 40)

    if features.get("has_https") == 0 and (has_lure or deceptive or features.get("count_hyphens", 0) >= 2):
        score = max(score, 45)
    elif deceptive:
        score = max(score, 50)

    if url_existence:
        exists = url_existence.get("exists")
        dns_resolved = url_existence.get("dns_resolved", False)
        http_status = url_existence.get("http_status")
        if exists is False and not dns_resolved:
            score = max(score, 75)
        elif dns_resolved and exists is False and http_status in (404, 410):
            score = max(score, 45)
        elif url_existence.get("ssl_error"):
            score = max(score, 60)

    return min(100, score)


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

    brand_hit = detect_brand_impersonation(domain)
    if brand_hit:
        impersonated_brand, brand_reason = brand_hit
        reasons.append(brand_reason)

    has_deceptive_word = has_deceptive_host_words(domain)
    if has_deceptive_word:
        reasons.append("Hostname contains deceptive/mock threat terminology.")

    if features.get("has_ip") == 1:
        reasons.append("Uses a raw IP address instead of a verified domain name.")
    if features.get("is_punycode") == 1:
        reasons.append("Uses Punycode ('xn--') encoding which can visually mimic legitimate domains.")
    if features.get("has_at_symbol") == 1:
        reasons.append("Contains '@' in the URL authority section to mask the true destination host.")
    if features.get("has_suspicious_tld") == 1:
        tld = domain.split(".")[-1] if "." in domain else ""
        reasons.append(f"Registered under a high-abuse top-level domain (.{tld}).")
    all_url_tokens = {
        t for t in re.split(r"[^a-z0-9-]+", (normalized_url or "").lower()) if t
    }
    matched_action_keywords = sorted(all_url_tokens & ACTION_LURE_KEYWORDS)
    if matched_action_keywords:
        reasons.append(
            f"Contains sensitive authentication or credential-lure keywords ({', '.join(matched_action_keywords[:4])})."
        )
    if features.get("has_https") == 0:
        reasons.append("Lacks HTTPS encryption (unencrypted HTTP transport).")

    existence_note: Optional[str] = None
    domain_not_found = False
    page_not_found = False
    if url_existence:
        http_status = url_existence.get("http_status")
        dns_resolved = url_existence.get("dns_resolved", False)
        exists = url_existence.get("exists")
        if exists is True and http_status is not None:
            if url_existence.get("ssl_error"):
                reasons.append(f"Live HTTPS responded (HTTP {http_status}), but the SSL/TLS certificate failed validation.")
            else:
                existence_note = f"Live server responded (HTTP {http_status})."
        elif dns_resolved and exists is False and http_status in (404, 410):
            page_not_found = True
            reasons.append(
                f"Domain resolved, but this specific URL returned HTTP {http_status} (page not found)."
            )
        elif exists is False and not dns_resolved:
            domain_not_found = True
            reasons.append("Live DNS check confirmed this domain does not exist or is unregistered.")

    has_lure_with_http = (
        features.get("has_https") == 0
        and (bool(matched_action_keywords) or has_deceptive_word or features.get("count_hyphens", 0) >= 2)
    )
    has_ssl_error = bool(url_existence and url_existence.get("ssl_error"))
    is_shortened = features.get("is_shortened") == 1

    # Decision synthesis
    if risk_score >= 70 or classification == "Phishing" or impersonated_brand is not None or features.get("has_at_symbol") == 1:
        verdict = "Fake"
        label = "Likely Fake (Phishing)"
        tone = "fake"
        summary = (
            f"This URL is classified as likely fake/phishing (Risk Score: {risk_score}/100). "
            "Do not enter credentials or personal details."
        )
        if not reasons:
            reasons.append("Machine learning and structural heuristics strongly match phishing patterns.")
    elif domain_not_found:
        verdict = "Fake"
        label = "Fake / Non-Existent Domain"
        tone = "fake"
        summary = (
            "Live DNS verification confirmed this domain does not exist. "
            "Treat this URL as invalid or fake."
        )
    elif risk_score >= 35 or classification == "Suspicious" or page_not_found or has_lure_with_http or has_deceptive_word or has_ssl_error or is_shortened:
        verdict = "Suspicious"
        label = "Suspicious (Could Be Fake)"
        tone = "suspicious"
        if is_shortened and not reasons:
            reasons.append("Uses a URL shortening service that hides the true destination domain.")
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
