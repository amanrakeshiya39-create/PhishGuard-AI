"""
PhishGuard AI - URL Sanitization and Validation
Provides resilient normalization, sanity checking, and malformed URL detection.
Guarantees the system never crashes on invalid, truncated, or hostile inputs.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple

# Standard regex for domain and IP validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
LOCAL_OR_HOSTNAME_REGEX = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

def normalize_url(raw_url: str) -> str:
    """
    Trims, cleans, and standardizes a URL string.
    Automatically prepends 'http://' if scheme is omitted for proper parsing.
    """
    if not raw_url:
        raise ValueError("URL cannot be empty.")

    cleaned = raw_url.strip()

    # Reject null bytes and common injection attempts
    if "\x00" in cleaned or "\r" in cleaned or "\n" in cleaned:
        raise ValueError("URL contains invalid control characters.")

    # Guard against non-web protocols
    lowered = cleaned.lower()
    if lowered.startswith(("javascript:", "data:", "file:", "vbscript:", "about:")):
        raise ValueError("Unsupported or insecure URI scheme detected. Only HTTP/HTTPS URLs are allowed.")

    # Add default scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned

    return cleaned


def is_valid_ip(host: str) -> bool:
    """Checks whether the hostname is a valid IPv4 or IPv6 address."""
    # Strip port if present in host string
    host_clean = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False


def validate_and_parse_url(raw_url: str) -> Tuple[str, str]:
    """
    Validates the structure of a URL and returns (normalized_url, domain).
    Raises ValueError with descriptive human-readable message on validation failure.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    if len(raw_url) > 2048:
        raise ValueError("URL exceeds maximum length of 2048 characters.")

    normalized = normalize_url(raw_url)

    try:
        parsed = urlparse(normalized)
    except Exception as exc:
        raise ValueError(f"Malformed URL structure: {str(exc)}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS protocols are supported.")

    netloc = parsed.netloc.strip()
    if not netloc:
        raise ValueError("Invalid URL: Missing hostname or domain.")

    # Extract domain (strip port and credentials if present)
    host = netloc
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]

    host = host.lower().strip(".")

    if not host:
        raise ValueError("Invalid URL: Hostname cannot be empty.")

    # Check if host is valid IP or valid domain pattern
    if not is_valid_ip(host):
        # Allow localhost for local development testing
        if host == "localhost":
            return normalized, host

        # Punycode check / Internationalized Domain Name handling
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except Exception:
            raise ValueError(f"Invalid domain characters or punycode format in '{host}'.")

        if not DOMAIN_REGEX.match(ascii_host):
            raise ValueError(f"Invalid domain format: '{host}'. Must be a valid domain name (e.g., example.com) or IP address.")

    return normalized, host
