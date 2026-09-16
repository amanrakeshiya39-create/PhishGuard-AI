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
