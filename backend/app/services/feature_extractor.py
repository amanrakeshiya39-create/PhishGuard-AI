"""
PhishGuard AI - URL Feature Extraction Engine
=============================================
Module: ml.feature_extractor

This module extracts structural, lexical, and security-oriented features from a
given URL string. The extracted features serve as numerical inputs for machine
learning classifiers (e.g., Random Forest) and rule-based heuristic engines.

Design Principles:
- 100% Python Standard Library (no external APIs or network calls).
- Safe parsing: never crashes on None, empty strings, or malformed URLs.
- Type annotations and clear docstrings for academic evaluation.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Optional

# List of sensitive action keywords frequently observed in phishing lures
SUSPICIOUS_KEYWORDS: List[str] = [
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
    "support",
    "service",
    "recovery",
    "suspended",
    "validate",
    "unlock",
    "paypal",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "amazon",
    "chase",
    "wellsfargo",
]

# Known public URL shortening domains commonly abused to obscure true destinations
URL_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "rb.gy",
    "cutt.ly",
    "tiny.cc",
}

# Top-level domains statistically overrepresented in phishing and spam campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "buzz",
    "work",
    "fit",
    "monster",
    "club",
    "country",
    "stream",
    "bid",
    "download",
    "review",
    "link",
    "live",
    "click",
    "surf",
    "quest",
    "icu",
}

# Standardized numerical feature columns used for machine learning training and inference
FEATURE_COLUMNS: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dots",
    "count_hyphens",
    "count_digits",
    "count_special_chars",
    "has_https",
    "has_at_symbol",
    "count_at",
    "has_ip",
    "subdomain_count",
    "has_suspicious_keywords",
    "suspicious_keyword_count",
    "has_suspicious_tld",
    "is_shortened",
    "has_non_standard_port",
    "has_double_slash_redirect",
    "url_entropy",
]


def is_ip_address(hostname: Optional[str]) -> bool:
    """
    Determines whether a hostname string is a valid IPv4 or IPv6 address.

    Attackers frequently host phishing pages directly on compromised IP addresses
    rather than registered domain names to evade domain reputation blocklists.

    Args:
        hostname: The hostname or IP string extracted from the URL.

    Returns:
        True if the hostname represents a valid IPv4/IPv6 address, False otherwise.
    """
    if not hostname:
        return False

    raw_host = hostname.strip()

    # 1. Check bracketed IPv6 with port e.g. "[2001:db8::1]:8080"
    if raw_host.startswith("[") and "]" in raw_host:
        ip_inside = raw_host[1 : raw_host.index("]")]
        try:
            ipaddress.ip_address(ip_inside)
            return True
        except ValueError:
            pass

    # 2. Check bare IP without brackets or ports
    bare_host = raw_host.strip("[]")
    try:
        ipaddress.ip_address(bare_host)
        return True
    except ValueError:
        pass

    # 3. Check IPv4 with port e.g. "192.168.1.1:8080"
    if ":" in bare_host:
        parts = bare_host.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            try:
                ipaddress.ip_address(parts[0])
                return True
            except ValueError:
                pass

    return False


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon character entropy of a given string.

    Higher entropy values indicate greater randomness in character distribution.
    Phishing kits and malware often employ Domain Generation Algorithms (DGA)
    or randomized token strings that exhibit unnaturally high entropy.

    Args:
        text: The input string (URL).

    Returns:
        The Shannon entropy as a float (rounded to 4 decimal places).
    """
    if not text:
        return 0.0

    length = len(text)
    frequencies: Dict[str, int] = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def extract_features(raw_url: Optional[str]) -> Dict[str, Any]:
    """
    Safely parses a URL string and extracts comprehensive security-oriented features.

    This function is guaranteed never to raise unhandled exceptions or crash the
    application when presented with malformed, empty, or non-string inputs.

    Args:
        raw_url: The URL string to inspect.

    Returns:
        A structured dictionary containing all extracted lexical, structural,
        and heuristic features.
    """
    # 0. Defensive Handling of Empty or Non-String Inputs
    if raw_url is None or not isinstance(raw_url, str) or not raw_url.strip():
        return _get_empty_features(str(raw_url) if raw_url is not None else "")

    cleaned_url = raw_url.strip()

    # Reject dangerous non-HTTP URI schemes or control character injections
    if any(ctrl in cleaned_url for ctrl in ("\x00", "\r", "\n")):
        return _get_empty_features(cleaned_url)

    try:
        lowered_url = cleaned_url.lower()

        # 1. Safe Normalization & Scheme Prepending
        # If scheme is omitted (e.g., 'example.com/login'), prepend 'http://' for safe parsing
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
            normalized_url = "http://" + cleaned_url
        else:
            normalized_url = cleaned_url

        # 2. Safe Parsing using urllib.parse
        parsed = urlparse(normalized_url)

        # Extract parsed components safely
        scheme = (parsed.scheme or "").lower()
        netloc = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Extract clean hostname (strip credentials and port)
        hostname = netloc
        if "@" in hostname:
            hostname = hostname.split("@")[-1]
        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.split(":")[0]
        hostname = hostname.lower().strip(".")

        # 3. Lexical Features
        url_length: int = len(cleaned_url)
        hostname_length: int = len(hostname)
        path_length: int = len(path)
        query_length: int = len(query)

        # Character counts
        count_dots: int = cleaned_url.count(".")
        count_hyphens: int = cleaned_url.count("-")
        count_digits: int = sum(1 for c in cleaned_url if c.isdigit())
        count_at: int = cleaned_url.count("@")

        # Special characters: non-alphanumeric and not whitespace
        count_special_chars: int = sum(
            1 for c in cleaned_url if not c.isalnum() and not c.isspace()
        )

        # 4. Protocol & Security Checks
        has_https: int = 1 if scheme == "https" else 0
        has_at_symbol: int = 1 if count_at > 0 else 0
        has_ip: int = 1 if is_ip_address(hostname) else 0

        # 5. Subdomain Hierarchy
        # If host is an IP address, subdomains are not applicable (0)
        # For a domain 'a.b.example.com', splitting by '.' gives 4 parts -> 2 subdomains
        if has_ip or not hostname:
            subdomain_count = 0
        else:
            domain_parts = [p for p in hostname.split(".") if p]
            subdomain_count = max(0, len(domain_parts) - 2)

        # 6. Suspicious Keyword Detection
        detected_keywords: List[str] = [
            kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered_url
        ]
        suspicious_keyword_count: int = len(detected_keywords)
        has_suspicious_keywords: int = 1 if suspicious_keyword_count > 0 else 0

        # 7. Suspicious TLD & URL Shortener Detection
        tld = hostname.split(".")[-1] if "." in hostname else ""
        has_suspicious_tld: int = 1 if tld in SUSPICIOUS_TLDS else 0
        is_shortened: int = 1 if hostname in URL_SHORTENERS else 0

        # 8. Path Redirection, Port Anomalies, and Punycode
        path_after_scheme = normalized_url[len(scheme) + 3 :]
        has_double_slash_redirect: int = 1 if "//" in path_after_scheme else 0
        is_punycode: int = 1 if "xn--" in hostname else 0

        has_non_standard_port: int = 0
        try:
            port = parsed.port
            if port and port not in (80, 443):
                has_non_standard_port = 1
        except (ValueError, TypeError):
            # Non-numeric port string (e.g. malformed URI)
            has_non_standard_port = 1

        # 9. Shannon Entropy
        url_entropy: float = calculate_entropy(cleaned_url)

        # 10. Assemble and Return Structured Dictionary
        return {
            "url": cleaned_url,
            "hostname": hostname,
            "url_length": url_length,
            "hostname_length": hostname_length,
            "domain_length": hostname_length,
            "path_length": path_length,
            "query_length": query_length,
            "count_dots": count_dots,
            "count_hyphens": count_hyphens,
            "count_digits": count_digits,
            "count_special_chars": count_special_chars,
            "has_https": has_https,
            "has_at_symbol": has_at_symbol,
            "count_at": count_at,
            "has_ip": has_ip,
            "subdomain_count": subdomain_count,
            "count_subdomains": subdomain_count,
            "has_suspicious_keywords": has_suspicious_keywords,
            "suspicious_keyword_count": suspicious_keyword_count,
            "detected_keywords": detected_keywords,
            "has_suspicious_tld": has_suspicious_tld,
            "is_shortened": is_shortened,
            "has_non_standard_port": has_non_standard_port,
            "has_double_slash_redirect": has_double_slash_redirect,
            "is_punycode": is_punycode,
            "url_entropy": url_entropy,
        }
    except Exception:
        # Fall back to zero-filled safe default on any unhandled error
        return _get_empty_features(cleaned_url)


def get_feature_names() -> List[str]:
    """Returns the ordered list of 20 numerical features used for machine learning."""
    return list(FEATURE_COLUMNS)


def _get_empty_features(raw_url: str) -> Dict[str, Any]:
    """
    Returns a safe zero-filled dictionary for invalid or empty inputs.
    Guarantees consistent schema without throwing exceptions.
    """
    return {
        "url": raw_url,
        "hostname": "",
        "url_length": len(raw_url) if raw_url else 0,
        "hostname_length": 0,
        "domain_length": 0,
        "path_length": 0,
        "query_length": 0,
        "count_dots": 0,
        "count_hyphens": 0,
        "count_digits": 0,
        "count_special_chars": 0,
        "has_https": 0,
        "has_at_symbol": 0,
        "count_at": 0,
        "has_ip": 0,
        "subdomain_count": 0,
        "count_subdomains": 0,
        "has_suspicious_keywords": 0,
        "suspicious_keyword_count": 0,
        "detected_keywords": [],
        "has_suspicious_tld": 0,
        "is_shortened": 0,
        "has_non_standard_port": 0,
        "has_double_slash_redirect": 0,
        "is_punycode": 0,
        "url_entropy": 0.0,
    }
