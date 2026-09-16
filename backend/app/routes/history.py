"""
PhishGuard AI - History Route Endpoints
Handles paginated scan history listing, search filtering, and deletion.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.models.scan import ScanHistoryResponse, ScanHistoryItem
from app.services.db_service import get_scan_history, delete_scan_record

router = APIRouter(prefix="/history", tags=["History"])


@router.get("", response_model=ScanHistoryResponse)
async def list_history(
    limit: int = Query(20, ge=1, le=100, description="Number of results to return"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    classification: Optional[str] = Query(None, description="Filter by classification: 'Low Risk', 'Suspicious', 'Phishing'"),
    search: Optional[str] = Query(None, description="Search query against URL or domain")
):
    """Fetches paginated list of previous URL scans."""
    items, total = await get_scan_history(
        limit=limit,
        skip=skip,
        classification=classification,
        search=search
    )

    history_items = [
        ScanHistoryItem(
            id=item["id"],
            url=item.get("url", ""),
            domain=item.get("domain", ""),
            risk_score=item.get("risk_score", 0),
            classification=item.get("classification", "Unknown"),
            confidence=item.get("confidence", 0.0),
            scanned_at=item.get("scanned_at", "")
        )
        for item in items
    ]

    return ScanHistoryResponse(
        status="success",
        total=total,
        items=history_items
    )


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(scan_id: str):
    """Deletes a specific scan record from the history database."""
    deleted = await delete_scan_record(scan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found."
        )

    return {
        "status": "success",
        "message": f"Scan record '{scan_id}' successfully deleted."
    }
