"""
PhishGuard AI - Dashboard Statistics Route
Provides aggregated analytics on scans, risk distributions, and top flagged threats.
"""

from fastapi import APIRouter
from app.models.stats import DashboardStatsResponse, DashboardStatsData
from app.services.db_service import calculate_dashboard_stats

router = APIRouter(prefix="/stats", tags=["Dashboard"])


@router.get("", response_model=DashboardStatsResponse)
async def get_dashboard_stats():
    """Retrieves aggregated metrics and threat distributions for the dashboard."""
    stats = await calculate_dashboard_stats()
    return DashboardStatsResponse(
        status="success",
        data=DashboardStatsData(**stats)
    )
