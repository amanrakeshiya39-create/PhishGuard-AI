"""
PhishGuard AI - Pydantic Data Models for Dashboard Statistics
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field


class FlaggedFactorCount(BaseModel):
    factor: str
    count: int


class DashboardStatsData(BaseModel):
    total_scans: int
    phishing_count: int
    suspicious_count: int
    low_risk_count: int
    phishing_percentage: float
    suspicious_percentage: float
    low_risk_percentage: float
    average_risk_score: float
    top_flagged_factors: List[FlaggedFactorCount]
    is_database_connected: bool


class DashboardStatsResponse(BaseModel):
    status: str = "success"
    data: DashboardStatsData
