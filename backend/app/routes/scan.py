"""
PhishGuard AI - Scan Route Endpoints
Handles URL risk scanning, validation, and individual report retrieval.
"""

from fastapi import APIRouter, HTTPException, status
from app.models.scan import URLScanRequest, URLScanResponse, URLScanResponseData
from app.services.predictor import predict_url_risk
from app.services.explainer import generate_explanation
from app.services.url_checker import check_url_existence
from app.services.authenticity import (
    apply_authenticity_risk_guardrails,
    assess_url_authenticity,
)
from app.services.db_service import save_scan_record, get_scan_by_id
from app.utils.constants import (
    LABEL_LOW_RISK,
    LABEL_PHISHING,
    LABEL_SUSPICIOUS,
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_SUSPICIOUS,
)

router = APIRouter(prefix="/scan", tags=["Scanning"])


@router.post("", response_model=URLScanResponse, status_code=status.HTTP_200_OK)
async def scan_url(payload: URLScanRequest):
    """
    Submits a URL for comprehensive phishing and threat analysis.
    Extracts 20 features, runs the Random Forest model, computes risk score,
    generates an explainable report, and persists the record to the database.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty."
        )

    try:
        # Run prediction, live existence check, and explainability pipeline
        result = predict_url_risk(payload.url)
        existence = await check_url_existence(result["normalized_url"], result["domain"])
        result["url_existence"] = existence

        aligned_score = apply_authenticity_risk_guardrails(
            domain=result["domain"],
            normalized_url=result["normalized_url"],
            features=result["features"],
            risk_score=result["risk_score"],
            url_existence=existence,
        )
        result["risk_score"] = aligned_score
        if aligned_score <= RISK_THRESHOLD_LOW:
            result["classification"] = LABEL_LOW_RISK
        elif aligned_score <= RISK_THRESHOLD_SUSPICIOUS:
            result["classification"] = LABEL_SUSPICIOUS
        else:
            result["classification"] = LABEL_PHISHING

        result["explanation"] = generate_explanation(
            result["features"],
            result["risk_score"],
            result["domain"],
            url_existence=existence,
        )
        authenticity = assess_url_authenticity(
            domain=result["domain"],
            normalized_url=result["normalized_url"],
            features=result["features"],
            risk_score=result["risk_score"],
            classification=result["classification"],
            confidence=result["confidence"],
            url_existence=existence,
        )
        result["authenticity"] = authenticity
        result["verdict"] = authenticity["verdict"]
    except ValueError as val_err:
        # User-friendly validation error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {str(val_err)}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(exc)}"
        )

    # Persist to database
    scan_id = await save_scan_record(result)
    result["id"] = scan_id

    return URLScanResponse(
        status="success",
        data=URLScanResponseData(**result)
    )


@router.get("/{scan_id}", response_model=URLScanResponse, status_code=status.HTTP_200_OK)
async def get_scan_details(scan_id: str):
    """Retrieves full analysis details for an existing scan by its ID."""
    doc = await get_scan_by_id(scan_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    return URLScanResponse(
        status="success",
        data=URLScanResponseData(**doc)
    )
