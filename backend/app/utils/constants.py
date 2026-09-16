"""
PhishGuard AI - Constants and Heuristics Definitions
Defines suspicious keywords, high-risk TLDs, URL shorteners, and thresholds.
"""

from typing import List, Set

# Keywords frequently present in phishing lures targeting sensitive accounts
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

# Known public URL shortening services commonly abused to obscure destinations
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

# Risk score thresholds and categorical labels
RISK_THRESHOLD_LOW: int = 34
RISK_THRESHOLD_SUSPICIOUS: int = 69

LABEL_LOW_RISK: str = "Low Risk"
LABEL_SUSPICIOUS: str = "Suspicious"
LABEL_PHISHING: str = "Phishing"

# Standard disclaimer complying with cybersecurity project guidelines
SAFETY_DISCLAIMER: str = (
    "This assessment is a probabilistic estimate generated via machine learning "
    "and structural heuristic analysis. It does not constitute a 100% guarantee of safety. "
    "Always exercise caution and verify authenticity through official channels before entering credentials."
)
