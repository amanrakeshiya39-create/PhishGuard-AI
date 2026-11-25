"""
Unit and integration tests for FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["ml_model_loaded"] is True


def test_scan_legitimate_url():
    response = client.post("/api/v1/scan", json={"url": "https://wikipedia.org"})
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "success"
    data = res["data"]
    assert "risk_score" in data
    assert data["classification"] in ("Low Risk", "Suspicious", "Phishing")
    assert "disclaimer" in data
    assert len(data["features"]) >= 20
    assert "url_existence" in data
    assert "status" in data["url_existence"]
    assert "dns_resolved" in data["url_existence"]
    assert "authenticity" in data
    assert data["authenticity"]["verdict"] in ("Real", "Suspicious", "Fake")
    assert data["authenticity"]["verdict"] == "Real"
    assert data["authenticity"]["label"] == "Likely Real"


def test_scan_phishing_url():
    response = client.post(
        "/api/v1/scan",
        json={"url": "http://paypal-security-verification.xyz/login.php"}
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["classification"] == "Phishing"
    assert data["risk_score"] >= 70
    assert len(data["explanation"]["risk_factors"]) > 0
    assert data["authenticity"]["verdict"] == "Fake"
    assert data["authenticity"]["brand_impersonation"] == "paypal"


def test_scan_invalid_url_returns_400():
    response = client.post("/api/v1/scan", json={"url": "not-a-valid-url"})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_history_and_stats_endpoints():
    # History
    hist_resp = client.get("/api/v1/history?limit=5")
    assert hist_resp.status_code == 200
    assert hist_resp.json()["status"] == "success"

    # Stats
    stats_resp = client.get("/api/v1/stats")
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()["data"]
    assert "total_scans" in stats_data
    assert "average_risk_score" in stats_data


def test_threats_catalog_endpoint():
    resp = client.get("/api/v1/threats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    data = body["data"]
    assert data["total_threats"] >= 10
    assert "severity_breakdown" in data
    assert len(data["threats"]) == data["total_threats"]
    first = data["threats"][0]
    for key in ("id", "name", "category", "severity", "description", "example", "mitigation", "detected_count"):
        assert key in first


def test_url_existence_checker_handles_existing_and_missing(monkeypatch):
    import asyncio
    import socket
    from app.services import url_checker

    async def fake_getaddrinfo_ok(self, host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    async def fake_getaddrinfo_missing(self, host, port, **kwargs):
        if host in ("example.com", "google.com"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise socket.gaierror(8, "nodename nor servname provided, or not known")

    async def fake_getaddrinfo_offline(self, host, port, **kwargs):
        raise socket.gaierror(8, "nodename nor servname provided, or not known")

    monkeypatch.setattr(
        url_checker,
        "_probe_http",
        lambda url, timeout=2.5: {
            "http_status": 200,
            "final_url": url,
            "response_time_ms": 42,
            "ssl_error": False,
        },
    )

    async def _run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(type(loop), "getaddrinfo", fake_getaddrinfo_ok)
        res_ok = await url_checker.check_url_existence("https://example.com", "example.com")
        assert res_ok["exists"] is True
        assert res_ok["dns_resolved"] is True
        assert res_ok["http_status"] == 200
        assert res_ok["resolved_ip"] == "93.184.216.34"

        monkeypatch.setattr(type(loop), "getaddrinfo", fake_getaddrinfo_missing)
        res_missing = await url_checker.check_url_existence(
            "http://does-not-exist-9999.xyz", "does-not-exist-9999.xyz"
        )
        assert res_missing["exists"] is False
        assert res_missing["dns_resolved"] is False
        assert "Does Not Exist" in res_missing["status"]

        monkeypatch.setattr(type(loop), "getaddrinfo", fake_getaddrinfo_offline)
        res_offline = await url_checker.check_url_existence("https://wikipedia.org", "wikipedia.org")
        assert res_offline["exists"] is None
        assert "Unavailable" in res_offline["status"]

    asyncio.run(_run())


def test_authenticity_verdict_detects_typosquat_fake_and_official_real():
    from app.services.authenticity import assess_url_authenticity

    fake_res = assess_url_authenticity(
        domain="paypa1-secure.com",
        normalized_url="http://paypa1-secure.com/login",
        features={"has_ip": 0, "is_punycode": 0, "has_at_symbol": 0, "has_suspicious_tld": 0, "has_https": 0},
        risk_score=25,
        classification="Low Risk",
        confidence=0.75,
    )
    assert fake_res["verdict"] == "Fake"
    assert fake_res["brand_impersonation"] == "paypal"

    # Non-existent domain confirmed via DNS should be Fake
    nxdomain_res = assess_url_authenticity(
        domain="nonexistent-bank-9999.com",
        normalized_url="https://nonexistent-bank-9999.com",
        features={"has_ip": 0, "is_punycode": 0, "has_at_symbol": 0, "has_suspicious_tld": 0, "has_https": 1},
        risk_score=5,
        classification="Low Risk",
        confidence=0.95,
        url_existence={"exists": False, "dns_resolved": False, "http_status": None},
    )
    assert nxdomain_res["verdict"] == "Fake"

    # Official multi-part TLD and ordinary words like 'purchase.com' must stay Real
    for ok_domain in ("google.com", "www.amazon.co.uk", "purchase.com"):
        real_res = assess_url_authenticity(
            domain=ok_domain,
            normalized_url=f"https://{ok_domain}",
            features={"has_ip": 0, "is_punycode": 0, "has_at_symbol": 0, "has_suspicious_tld": 0, "has_https": 1},
            risk_score=5,
            classification="Low Risk",
            confidence=0.95,
        )
        assert real_res["verdict"] == "Real", f"Expected Real for {ok_domain}, got {real_res}"
        assert real_res["brand_impersonation"] is None
