"""
PhishGuard AI - Model Training Pipeline
Extracts features from dataset, trains a Random Forest Classifier,
evaluates performance metrics, and serializes the model and metadata.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.feature_extractor import extract_features, get_feature_names


def train_model():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "dataset", "phishing_urls.csv")
    models_dir = os.path.join(base_dir, "saved_models")
    os.makedirs(models_dir, exist_ok=True)

    model_output_path = os.path.join(models_dir, "rf_model.joblib")
    meta_output_path = os.path.join(models_dir, "feature_meta.json")

    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    print(f"[+] Loaded {len(df)} records. Extracting 20 features per URL...")

    feature_records = []
    labels = []
    valid_feature_names = get_feature_names()

    for idx, row in df.iterrows():
        url = row["url"]
        label = row["label"]
        try:
            feats = extract_features(url)
            feature_records.append([feats[name] for name in valid_feature_names])
            labels.append(label)
        except Exception as e:
            # Skip any malformed row without stopping the pipeline
            continue

    X = np.array(feature_records)
    y = np.array(labels)
    print(f"[+] Feature matrix shape: {X.shape}")

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Training set size: {X_train.shape[0]}, Test set size: {X_test.shape[0]}")

    print("[*] Training Random Forest Classifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n=======================================================")
    print("           MODEL EVALUATION REPORT                     ")
    print("=======================================================")
    print(f"Accuracy:        {acc * 100:.2f}%")
    print(f"Precision:       {prec * 100:.2f}%")
    print(f"Recall:          {rec * 100:.2f}%")
    print(f"F1-Score:        {f1 * 100:.2f}%")
    print(f"ROC-AUC:         {roc_auc:.4f}")
    print(f"Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
    print("-------------------------------------------------------")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("=======================================================\n")

    # Feature Importance
    importances = clf.feature_importances_
    importance_map = {name: round(float(imp), 4) for name, imp in zip(valid_feature_names, importances)}
    sorted_importances = sorted(importance_map.items(), key=lambda item: item[1], reverse=True)

    print("[*] Top 10 Contributing Features:")
    for rank, (name, imp) in enumerate(sorted_importances[:10], 1):
        print(f"   {rank:2d}. {name:<26} : {imp:.4f}")

    # Serialize model
    print(f"\n[*] Saving trained model to: {model_output_path}")
    joblib.dump(clf, model_output_path)

    # Save feature metadata and metrics
    meta = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 15,
        "features": valid_feature_names,
        "feature_importances": importance_map,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "confusion_matrix": cm,
            "total_samples": len(df),
            "test_samples": len(y_test)
        },
        "trained_at": datetime.utcnow().isoformat() + "Z"
    }

    with open(meta_output_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Successfully saved metadata to: {meta_output_path}")
    print("[+] Model training pipeline complete!\n")


if __name__ == "__main__":
    train_model()
