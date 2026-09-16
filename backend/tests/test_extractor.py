"""
Unit tests for Feature Extractor.
"""

from app.services.feature_extractor import extract_features, calculate_entropy, get_feature_names


def test_feature_names_count():
    names = get_feature_names()
    assert len(names) == 20


def test_extract_features_structure():
    url = "https://secure-login.bank.example.xyz/account/verify?token=123"
    feats = extract_features(url)
    assert len(feats) >= 20
    assert feats["has_https"] == 1
    assert feats["has_suspicious_tld"] == 1  # .xyz
    assert feats["has_suspicious_keywords"] == 1
    assert feats["suspicious_keyword_count"] >= 2
    assert feats["count_subdomains"] >= 2
    assert feats["count_dots"] >= 3
    assert feats["count_hyphens"] >= 1


def test_ip_detection():
    url = "http://192.168.1.1:8080/login"
    feats = extract_features(url)
    assert feats["has_ip"] == 1
    assert feats["has_non_standard_port"] == 1
    assert feats["has_https"] == 0


def test_shannon_entropy():
    # Repetitive string has low entropy
    low_ent = calculate_entropy("aaaaaaa")
    # Random string has high entropy
    high_ent = calculate_entropy("a8b9c1d2e3f4g5")
    assert low_ent == 0.0
    assert high_ent > 3.0
