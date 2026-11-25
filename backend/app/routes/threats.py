"""
PhishGuard AI - Threat & Risk Catalog Route
Exposes all phishing and URL threat definitions with live detection counts.
"""

from fastapi import APIRouter
from app.services.db_service import get_all_scans_raw
from app.services.threat_catalog import build_threats_catalog_response

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get("")
async def get_all_threats():
    """
    Returns the complete catalog of threats monitored by PhishGuard AI,
    including severity, descriptions, examples, mitigations, and live hit counts.
    """
    all_scans = await get_all_scans_raw()
    data = build_threats_catalog_response(all_scans)
    return {
        "status": "success",
        "data": data,
    }
