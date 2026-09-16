"""
PhishGuard AI - Application Configuration
Minimal, dependency-free settings loader using python-dotenv and os.environ.
"""

import os
import json
from typing import List
from dotenv import load_dotenv

# Load .env if present
load_dotenv()


class Settings:
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "phishguard_db")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

    raw_cors = os.getenv("CORS_ORIGINS", '["*"]')
    try:
        CORS_ORIGINS: List[str] = json.loads(raw_cors)
    except Exception:
        CORS_ORIGINS: List[str] = ["*"]

    MODEL_PATH: str = os.getenv("MODEL_PATH", "ml/saved_models/rf_model.joblib")
    FEATURE_META_PATH: str = os.getenv("FEATURE_META_PATH", "ml/saved_models/feature_meta.json")


settings = Settings()
