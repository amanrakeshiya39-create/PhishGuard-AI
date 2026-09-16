"""
PhishGuard AI - Model Evaluation and Inspection Utility
Loads the trained Random Forest model and metadata, displaying model parameters,
feature importances, and sample predictions.
"""

import os
import sys
import json
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.feature_extractor import extract_features, get_feature_names


def inspect_model():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "saved_models", "rf_model.joblib")
    meta_path = os.path.join(base_dir, "saved_models", "feature_meta.json")

    if not os.path.exists(model_path):
        print(f"[!] Error: Model file not found at {model_path}. Run train.py first.")
        return

    model = joblib.load(model_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)

    print("=======================================================")
    print("           PHISHGUARD AI - MODEL INSPECTOR             ")
    print("=======================================================")
    print(f"Model Class:      {type(model).__name__}")
    print(f"Trees/Estimators: {model.n_estimators}")
    print(f"Max Depth:        {model.max_depth}")
    print(f"Features:         {len(meta['features'])}")
    print(f"Trained At:       {meta.get('trained_at', 'Unknown')}")
    print("-------------------------------------------------------")
    print("Metrics on Held-Out Test Set:")
    for k, v in meta.get("metrics", {}).items():
        if isinstance(v, float):
            print(f"  - {k:<18}: {v:.4f}")
        else:
            print(f"  - {k:<18}: {v}")
    print("-------------------------------------------------------")
    print("Feature Importance Ranking:")
    sorted_imps = sorted(meta["feature_importances"].items(), key=lambda x: x[1], reverse=True)
    for rank, (feat, imp) in enumerate(sorted_imps, 1):
        bar = "█" * int(imp * 50)
        print(f"  {rank:2d}. {feat:<26} : {imp:.4f} {bar}")
    print("=======================================================\n")


if __name__ == "__main__":
    inspect_model()
