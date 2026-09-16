"""
PhishGuard AI - Dataset Synthesis and Compilation Script
Generates a realistic, balanced dataset of legitimate and phishing URLs
representing real-world attack vectors and normal web behavior.
Output: backend/ml/dataset/phishing_urls.csv
"""

import os
import random
import string
import pandas as pd

random.seed(42)

LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "youtube.com", "stackoverflow.com", "reddit.com", "linkedin.com", "apple.com",
    "netflix.com", "nytimes.com", "bbc.co.uk", "mozilla.org", "python.org",
    "kaggle.com", "cloudflare.com", "medium.com", "docker.com", "gitlab.com",
    "quora.com", "yahoo.com", "spotify.com", "adobe.com", "dropbox.com",
    "wordpress.org", "bing.com", "salesforce.com", "slack.com", "zoom.us",
    "ebay.com", "cnn.com", "theguardian.com", "forbes.com", "nature.com",
    "stanford.edu", "mit.edu", "harvard.edu", "nih.gov", "nasa.gov",
    "w3schools.com", "digitalocean.com", "atlassian.com", "trello.com", "coursera.org"
]

LEGITIMATE_SUBDOMAINS = [
    "docs", "support", "developer", "api", "blog", "learn", "en", "m", "news",
    "account", "auth", "help", "store", "community", "mail", "cloud"
]

LEGITIMATE_PATHS = [
    "",
    "/",
    "/about",
    "/contact-us",
    "/terms",
    "/privacy-policy",
    "/docs/quickstart",
    "/docs/api/v2/reference",
    "/products/detail?id=10492",
    "/explore/trending",
    "/articles/2026/09/cybersecurity-overview",
    "/learn/python-data-science",
    "/user/dashboard",
    "/search?q=machine+learning+tutorial",
    "/settings/notifications",
    "/resources/whitepaper.pdf",
    "/categories/technology",
    "/feed.rss",
    "/faq",
    "/team/leadership"
]

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "facebook", "instagram",
    "binance", "metamask", "coinbase", "dhl", "fedex", "usps"
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "buzz", "club", "tk", "ml", "ga", "cf", "work",
    "monster", "country", "stream", "icu", "click", "surf", "fit"
]

ACTION_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account-update", "confirm-identity", "billing-resolve", "unlock-account",
    "suspended-notice", "auth-token", "wallet-connect", "credential-check"
]


def generate_random_token(length: int = 12) -> str:
    """Generates an alphanumeric token."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def generate_random_ip() -> str:
    """Generates a random public-like IPv4 address."""
    return f"{random.randint(11, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_legitimate_url() -> str:
    """Creates a realistic legitimate URL with normal structures and HTTPS."""
    domain = random.choice(LEGITIMATE_DOMAINS)
    has_sub = random.random() < 0.4
    if has_sub:
        sub = random.choice(LEGITIMATE_SUBDOMAINS)
        domain = f"{sub}.{domain}"

    path = random.choice(LEGITIMATE_PATHS)
    # Legitimate sites predominantly use HTTPS
    protocol = "https://" if random.random() < 0.95 else "http://"
    return f"{protocol}{domain}{path}"


def generate_phishing_url() -> str:
    """
    Creates a realistic phishing URL embodying known deceptive patterns:
    - Domain squatting and hyphenation
    - Multiple deceptive subdomains
    - High-abuse TLDs
    - Raw IP addresses with credential lures
    - Redirection tokens, non-standard ports, and Punycode
    """
    archetype = random.choice([
        "brand_squatting",
        "deep_subdomain",
        "ip_address",
        "suspicious_tld",
        "redirection_token",
        "punycode",
        "port_anomaly",
        "credential_auth_trick"
    ])

    brand = random.choice(TARGET_BRANDS)
    action = random.choice(ACTION_KEYWORDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    protocol = "http://" if random.random() < 0.85 else "https://"

    if archetype == "brand_squatting":
        # e.g., http://paypal-security-update-center.xyz/signin.php?token=92842
        token = generate_random_token(8)
        return f"{protocol}{brand}-{action}-{token}.{tld}/index.php?user={generate_random_token(6)}"

    elif archetype == "deep_subdomain":
        # e.g., http://login.microsoft.com.secure-portal-verify.top/account
        second_brand = random.choice(["service", "auth", "portal", "secure", "server"])
        return f"{protocol}{brand}.com.{action}.{second_brand}.{tld}/{action}.html"

    elif archetype == "ip_address":
        # e.g., http://192.168.1.50/login/chase-verify.php
        ip = generate_random_ip()
        port = f":{random.choice([8080, 8443, 8888, 3000])}" if random.random() < 0.4 else ""
        return f"http://{ip}{port}/{brand}/{action}.php?session_id={generate_random_token(16)}"

    elif archetype == "suspicious_tld":
        # e.g., http://netflix-billing-suspended.club/reactivate?id=38491
        rand_token = generate_random_token(10)
        return f"{protocol}{brand}-{action}.{tld}/login?redirect={rand_token}"

    elif archetype == "redirection_token":
        # e.g., http://attacker-portal.top//paypal.com/verify
        return f"{protocol}portal-{generate_random_token(6)}.{tld}//{brand}.com/{action}"

    elif archetype == "punycode":
        # e.g., http://xn--gogle-r4a.xyz/login
        punycode_host = f"xn--{brand[:4]}-{generate_random_token(3).lower()}.{tld}"
        return f"{protocol}{punycode_host}/{action}?uid={generate_random_token(8)}"

    elif archetype == "port_anomaly":
        # e.g., http://secure-amazon-verify.top:8080/auth
        return f"http://{brand}-{action}.{tld}:8080/{action}.html"

    else:  # credential_auth_trick
        # e.g., http://paypal.com@verify-account-gate.top/signin
        return f"http://{brand}.com@{action}-portal.{tld}/auth"


def build_dataset(total_samples: int = 4000, output_path: str = "backend/ml/dataset/phishing_urls.csv") -> None:
    """Synthesizes and exports a balanced dataset of legitimate (0) and phishing (1) URLs."""
    print(f"[*] Synthesizing {total_samples} balanced URL samples...")

    samples_per_class = total_samples // 2
    legit_set = set()
    phish_set = set()

    # Generate unique legitimate URLs
    while len(legit_set) < samples_per_class:
        legit_set.add(generate_legitimate_url())

    # Generate unique phishing URLs
    while len(phish_set) < samples_per_class:
        phish_set.add(generate_phishing_url())

    data = []
    for u in legit_set:
        data.append({"url": u, "label": 0})  # 0: Legitimate / Low Risk

    for u in phish_set:
        data.append({"url": u, "label": 1})  # 1: Phishing

    random.shuffle(data)
    df = pd.DataFrame(data)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Successfully saved {len(df)} records to '{output_path}'.")
    print(f"    - Legitimate (0): {len(legit_set)}")
    print(f"    - Phishing (1):   {len(phish_set)}")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_csv = os.path.join(current_dir, "phishing_urls.csv")
    build_dataset(total_samples=4000, output_path=output_csv)
