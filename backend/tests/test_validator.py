"""
Unit tests for URL Validator and Normalizer.
"""

import pytest
from app.utils.url_validator import validate_and_parse_url, normalize_url, is_valid_ip


def test_valid_urls():
    test_cases = [
        ("https://google.com", "https://google.com", "google.com"),
        ("http://sub.example.org/path?q=1", "http://sub.example.org/path?q=1", "sub.example.org"),
        ("wikipedia.org/wiki/Phishing", "http://wikipedia.org/wiki/Phishing", "wikipedia.org"),
        ("http://192.168.1.1/login", "http://192.168.1.1/login", "192.168.1.1"),
        ("http://localhost:8000/api", "http://localhost:8000/api", "localhost"),
    ]
    for raw, expected_norm, expected_domain in test_cases:
        norm, domain = validate_and_parse_url(raw)
        assert norm == expected_norm
        assert domain == expected_domain


def test_invalid_urls_raise_value_error():
    invalid_inputs = [
        "",
        "   ",
        "javascript:alert(1)",
        "data:text/html,<html></html>",
        "file:///etc/passwd",
        "http://",
        "not-a-valid-domain",
        "http://invalid domain with spaces.com",
        "a" * 2500,  # Exceeds max length
    ]
    for bad_input in invalid_inputs:
        with pytest.raises(ValueError):
            validate_and_parse_url(bad_input)


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("8.8.8.8:8080") is True
    assert is_valid_ip("256.300.1.1") is False
    assert is_valid_ip("example.com") is False
