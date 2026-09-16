"""
PhishGuard AI - Health and Liveness Route
"""

import os
from datetime import datetime, timezone
from fastapi import APIRouter
from app.database import db_manager
from app.services.predictor import get_model

router = APIRouter(prefix="/health", tags=["System"])


@router.get("")
async def health_check():
    """Returns the operational status of the API, ML model, and database."""
    ml_loaded = False
    try:
        model = get_model()
        ml_loaded = model is not None
    except Exception:
        ml_loaded = False

    return {
        "status": "healthy",
        "service": "PhishGuard AI Detection Engine",
        "version": "1.0.0",
        "ml_model_loaded": ml_loaded,
        "database_connected": db_manager.is_connected,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
