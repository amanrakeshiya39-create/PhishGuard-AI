"""
PhishGuard AI - Feature Extractor Unit Tests
============================================
Tests for ml/feature_extractor.py verifying robustness, feature correctness,
and resilience against malformed inputs.
"""

import pytest
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.feature_extractor import extract_features, is_ip_address, calculate_entropy


class TestFeatureExtractor:
    """Test suite for URL feature extraction."""

    def test_standard_legitimate_url(self):
        url = "https://www.wikipedia.org/wiki/Machine_learning"
        feats = extract_features(url)

        assert feats["url"] == url
        assert feats["hostname"] == "www.wikipedia.org"
        assert feats["url_length"] == len(url)
        assert feats["hostname_length"] == len("www.wikipedia.org")
        assert feats["has_https"] == 1
        assert feats["has_ip"] == 0
        assert feats["has_at_symbol"] == 0
        assert feats["count_at"] == 0
        assert feats["is_shortened"] == 0
        assert feats["count_dots"] >= 2
        assert feats["subdomain_count"] == 1  # 'www' subdomain

    def test_phishing_url_with_ip_address(self):
        url = "http://192.168.1.100:8080/bank/login.php"
        feats = extract_features(url)

        assert feats["has_ip"] == 1
        assert feats["has_https"] == 0
        assert feats["has_non_standard_port"] == 1
        assert feats["has_suspicious_keywords"] == 1
        assert "login" in feats["detected_keywords"] or "bank" in feats["detected_keywords"]
        assert feats["subdomain_count"] == 0  # IP hosts have 0 subdomains

    def test_suspicious_keywords_and_hyphens(self):
        url = "http://paypal-security-update-verify.com/signin/account"
        feats = extract_features(url)

        assert feats["count_hyphens"] == 3
        assert feats["has_suspicious_keywords"] == 1
        assert feats["suspicious_keyword_count"] >= 3
        assert "paypal" in feats["detected_keywords"]
        assert "verify" in feats["detected_keywords"]
        assert "security" in feats["detected_keywords"]

    def test_at_symbol_detection(self):
        url = "http://paypal.com@attacker-portal.net/auth"
        feats = extract_features(url)

        assert feats["has_at_symbol"] == 1
        assert feats["count_at"] == 1

    def test_url_shortener_detection(self):
        short_urls = [
            "https://bit.ly/3xY9zqA",
            "http://tinyurl.com/update-now",
            "https://t.co/xyz123"
        ]
        for u in short_urls:
            feats = extract_features(u)
            assert feats["is_shortened"] == 1, f"Failed for {u}"

    def test_query_length_and_parameters(self):
        url = "https://example.com/search?user=admin&token=9876543210"
        feats = extract_features(url)

        assert feats["query_length"] == len("user=admin&token=9876543210")
        assert feats["path_length"] == len("/search")

    def test_subdomain_count(self):
        url = "https://login.secure.staging.bank.example.com/auth"
        feats = extract_features(url)
        # login, secure, staging, bank, example, com -> 6 parts -> 4 subdomains
        assert feats["subdomain_count"] == 4

    def test_shannon_entropy_calculation(self):
        low_entropy_url = "http://aaaaa.com"
        high_entropy_url = "http://a8b9c1d2e3f4g5h6.com"

        low_feats = extract_features(low_entropy_url)
        high_feats = extract_features(high_entropy_url)

        assert high_feats["url_entropy"] > low_feats["url_entropy"]

    def test_resilience_on_malformed_and_none_inputs(self):
        malformed_inputs = [
            None,
            "",
            "   ",
            12345,
            {"url": "bad"},
            "javascript:alert(1)",
            "data:text/html,malicious",
            "http://",
            "http:///example.com",
            "\x00nullbyte.com",
            "http://[::1]:999999",  # Invalid port
            "htp://bad-protocol.xyz",
        ]

        for bad in malformed_inputs:
            # Must never raise an unhandled exception
            feats = extract_features(bad)
            assert isinstance(feats, dict)
            assert "url_length" in feats
            assert "has_ip" in feats
            assert "has_https" in feats
            assert "url_entropy" in feats

    def test_is_ip_address_helper(self):
        assert is_ip_address("192.168.1.1") is True
        assert is_ip_address("10.0.0.254:8080") is True
        assert is_ip_address("2001:db8::1") is True
        assert is_ip_address("example.com") is False
        assert is_ip_address("256.300.1.1") is False
        assert is_ip_address(None) is False
        assert is_ip_address("") is False
