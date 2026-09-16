"""
PhishGuard AI - Pydantic Data Models for URL Scans
Defines structured request and response models with validation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="The target URL or domain to evaluate.",
        json_schema_extra={"example": "https://secure-login-update.example.com/auth"}
    )


class RiskFactor(BaseModel):
    factor: str = Field(..., description="Short title of the identified risk trigger.")
    severity: str = Field(..., description="Risk severity: HIGH, MEDIUM, or LOW.")
    description: str = Field(..., description="Clear explanation of the cybersecurity risk.")


class ExplanationModel(BaseModel):
    summary: str = Field(..., description="High-level diagnostic summary.")
    risk_factors: List[RiskFactor] = Field(default_factory=list)


class URLScanResponseData(BaseModel):
    id: str = Field(..., description="Unique database identifier for this scan.")
    url: str = Field(..., description="Original input URL.")
    normalized_url: str = Field(..., description="Cleaned and standardized URL.")
    domain: str = Field(..., description="Extracted domain or IP host.")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100.")
    classification: str = Field(..., description="Low Risk, Suspicious, or Phishing.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model classification confidence.")
    probability_phishing: float = Field(..., ge=0.0, le=1.0, description="Estimated probability of phishing.")
    features: Dict[str, Any] = Field(..., description="All 20 extracted features.")
    explanation: ExplanationModel = Field(..., description="Explainable diagnostic breakdown.")
    disclaimer: str = Field(..., description="Mandatory safety advisory disclaimer.")
    scanned_at: str = Field(..., description="ISO 8601 UTC scan timestamp.")


class URLScanResponse(BaseModel):
    status: str = "success"
    data: URLScanResponseData


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    domain: str
    risk_score: int
    classification: str
    confidence: float
    scanned_at: str


class ScanHistoryResponse(BaseModel):
    status: str = "success"
    total: int
    items: List[ScanHistoryItem]
