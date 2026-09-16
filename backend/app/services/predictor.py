"""
PhishGuard AI - ML Prediction and Risk Scoring Service
Loads the trained Random Forest model, runs inference on extracted features,
applies heuristic safety guardrails, and outputs calibrated 0-100 risk scores.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional

from app.config import settings
from app.services.feature_extractor import extract_features, get_feature_names
from app.services.explainer import generate_explanation
from app.utils.constants import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_SUSPICIOUS,
    LABEL_LOW_RISK,
    LABEL_SUSPICIOUS,
    LABEL_PHISHING,
    SAFETY_DISCLAIMER,
)
from app.utils.url_validator import validate_and_parse_url

# Singleton model cache
_MODEL = None


def get_model():
    """Loads and caches the Random Forest model from disk."""
    global _MODEL
    if _MODEL is None:
        model_path = settings.MODEL_PATH
        if not os.path.isabs(model_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(base_dir, "..", model_path)
            model_path = os.path.normpath(model_path)

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Trained model not found at '{model_path}'. Please run ml/train.py first."
            )

        _MODEL = joblib.load(model_path)
    return _MODEL


def predict_url_risk(raw_url: str) -> Dict[str, Any]:
    """
    Complete analysis pipeline:
    1. Validates and normalizes URL
    2. Extracts 20 features
    3. Runs Random Forest classification
    4. Applies heuristic risk adjustments
    5. Computes explainable diagnostic feedback
    """
    normalized_url, domain = validate_and_parse_url(raw_url)
    features = extract_features(normalized_url)

    # Convert to ordered feature array
    feature_names = get_feature_names()
    feature_vector = np.array([[features[name] for name in feature_names]])

    # Inference
    model = get_model()
    probabilities = model.predict_proba(feature_vector)[0]
    # probabilities[0] is Legitimate (0), probabilities[1] is Phishing (1)
    p_phishing = float(probabilities[1])

    # Base continuous risk score (0 to 100)
    risk_score = int(round(p_phishing * 100))

    # Cybersecurity Heuristic Guardrails (Defense-in-depth)
    # If host is a raw IP address combined with keywords or non-standard port:
    if features.get("has_ip") == 1 and (features.get("has_suspicious_keywords") > 0 or features.get("has_non_standard_port") == 1):
        risk_score = max(risk_score, 85)

    # If Punycode homograph detected with security keyword:
    if features.get("is_punycode") == 1 and features.get("has_suspicious_keywords") > 0:
        risk_score = max(risk_score, 80)

    # If double slash redirection token detected:
    if features.get("has_double_slash_redirect") == 1:
        risk_score = max(risk_score, 75)

    # Classification Label
    if risk_score <= RISK_THRESHOLD_LOW:
        classification = LABEL_LOW_RISK
    elif risk_score <= RISK_THRESHOLD_SUSPICIOUS:
        classification = LABEL_SUSPICIOUS
    else:
        classification = LABEL_PHISHING

    # Confidence calculation: how decisively far from the decision boundary (0.5)
    confidence = round(float(max(probabilities[0], probabilities[1])), 2)

    # Explainability
    explanation = generate_explanation(features, risk_score, domain)

    return {
        "url": raw_url,
        "normalized_url": normalized_url,
        "domain": domain,
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "probability_phishing": round(p_phishing, 4),
        "features": features,
        "explanation": explanation,
        "disclaimer": SAFETY_DISCLAIMER,
        "scanned_at": "",
    }
