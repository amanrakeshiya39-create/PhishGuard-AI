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

    asyncio.run(_run())
