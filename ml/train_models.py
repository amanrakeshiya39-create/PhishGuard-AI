"""
PhishGuard AI - Multi-Model Machine Learning Training Pipeline
==============================================================
Module: ml.train_models

Trains and benchmarks three distinct machine learning classifiers on URL features:
1. Logistic Regression (Linear baseline with StandardScaler pipeline)
2. Decision Tree (Non-linear interpretable tree baseline)
3. Random Forest (Ensemble bagging classifier)

Key Engineering Safeguards:
- Strict 80/20 Stratified Train/Test Split.
- Zero Data Leakage: Scalers are fitted solely on training data.
- Class Imbalance Handling: Incorporates balanced class weights.
- Metric Evaluation: Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix.
- Serializes the winning model and feature order for backend serving.
- Non-Definitive Cybersecurity Advisory: Test accuracy does not guarantee universal security.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.feature_extractor import extract_features, FEATURE_COLUMNS


def load_dataset_and_extract_features(dataset_path: str) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """
    Loads dataset CSV and transforms raw URLs into a numerical feature matrix.
    Prevents data leakage by ensuring feature extraction relies purely on individual URL strings.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset CSV not found at '{dataset_path}'.")

    print(f"[*] Loading raw dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset CSV must contain 'url' and 'label' columns.")

    print(f"[+] Total raw records: {len(df)}")
    class_counts = df["label"].value_counts().to_dict()
    print(f"    - Class 0 (Legitimate): {class_counts.get(0, 0)} ({class_counts.get(0, 0) / len(df) * 100:.1f}%)")
    print(f"    - Class 1 (Phishing):   {class_counts.get(1, 0)} ({class_counts.get(1, 0) / len(df) * 100:.1f}%)")

    feature_rows = []
    labels = []

    print(f"[*] Extracting {len(FEATURE_COLUMNS)} numerical features using ml.feature_extractor...")
    for idx, row in df.iterrows():
        url = str(row["url"])
        label = int(row["label"])

        try:
            feats = extract_features(url)
            # Maintain strict column ordering from FEATURE_COLUMNS
            vector = [float(feats.get(col, 0.0)) for col in FEATURE_COLUMNS]
            feature_rows.append(vector)
            labels.append(label)
        except Exception as e:
            # Skip any malformed row without stopping the pipeline
            continue

    X = np.array(feature_rows, dtype=np.float64)
    y = np.array(labels, dtype=np.int64)

    print(f"[+] Feature extraction complete. Matrix shape: {X.shape}, Target shape: {y.shape}")
    return X, y, df


def build_models() -> Dict[str, Any]:
    """
    Constructs the three candidate classifiers with balanced class weighting.
    Logistic Regression is wrapped in a Pipeline with StandardScaler to avoid data leakage.
    """
    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                class_weight="balanced",
                max_iter=1000,
                random_state=42,
                solver="lbfgs"
            ))
        ]),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced",
            max_depth=15,
            min_samples_split=4,
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            class_weight="balanced",
            n_estimators=100,
            max_depth=15,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        ),
    }


def train_and_evaluate_pipeline():
    """
    Executes the complete machine learning training and evaluation lifecycle.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "dataset", "phishing_urls.csv")

    # Fallback to backend dataset directory if needed
    if not os.path.exists(dataset_path):
        dataset_path = os.path.join(base_dir, "..", "backend", "ml", "dataset", "phishing_urls.csv")

    saved_models_dir = os.path.join(base_dir, "saved_models")
    os.makedirs(saved_models_dir, exist_ok=True)

    # 1. Feature Extraction
    X, y, raw_df = load_dataset_and_extract_features(dataset_path)

    # 2. Train/Test Split (80% Train, 20% Test, Stratified to preserve class ratio)
    print("\n[*] Splitting dataset (80% Train, 20% Test, Stratified, random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Training set: {X_train.shape[0]} samples")
    print(f"[+] Testing set:  {X_test.shape[0]} samples")

    # 3. Model Training & Evaluation
    models = build_models()
    results: Dict[str, Dict[str, Any]] = {}

    print("\n" + "=" * 70)
    print("                MODEL TRAINING & EVALUATION BENCHMARK                 ")
    print("=" * 70)

    for name, model in models.items():
        print(f"\n[*] Training {name}...")
        # Fit model on training data ONLY
        model.fit(X_train, y_train)

        # Predict on unseen test set
        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        else:
            y_prob = model.decision_function(X_test)

        # Metrics
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        roc_auc = float(roc_auc_score(y_test, y_prob))
        cm = confusion_matrix(y_test, y_pred).tolist()

        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

        results[name] = {
            "model_object": model,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "confusion_matrix": {
                "TN": tn,
                "FP": fp,
                "FN": fn,
                "TP": tp,
            },
        }

        print(f"    - Accuracy:        {acc * 100:.2f}%")
        print(f"    - Precision:       {prec * 100:.2f}%")
        print(f"    - Recall:          {rec * 100:.2f}%")
        print(f"    - F1-Score:        {f1 * 100:.2f}%")
        print(f"    - ROC-AUC:         {roc_auc:.4f}")
        print(f"    - Confusion Matrix: TN={tn:<4} FP={fp:<4} FN={fn:<4} TP={tp:<4}")

    # 4. Tabular Model Comparison
    print("\n" + "=" * 70)
    print("                         MODEL COMPARISON                             ")
    print("=" * 70)
    header = f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8} | {'FN (Missed)'}"
    print(header)
    print("-" * len(header))

    for name, m in results.items():
        fn_count = m["confusion_matrix"]["FN"]
        print(
            f"{name:<22} | {m['accuracy']*100:>8.2f}% | {m['precision']*100:>8.2f}% | "
            f"{m['recall']*100:>7.2f}% | {m['f1_score']:>8.4f} | {m['roc_auc']:>8.4f} | {fn_count:>11}"
        )
    print("=" * 70)

    # 5. Model Selection (Highest F1-Score, lowest False Negatives, ensemble preference on ties)
    model_priority = {"Random Forest": 3, "Decision Tree": 2, "Logistic Regression": 1}
    best_model_name = max(
        results.keys(),
        key=lambda k: (
            results[k]["f1_score"],
            -results[k]["confusion_matrix"]["FN"],
            results[k]["roc_auc"],
            model_priority.get(k, 0)
        )
    )
    best_model_obj = results[best_model_name]["model_object"]

    print(f"\n[+] Selected Best Performing Model: '{best_model_name}'")

    # 6. Serialization
    model_save_path = os.path.join(saved_models_dir, "best_model.joblib")
    features_save_path = os.path.join(saved_models_dir, "feature_names.json")
    comparison_save_path = os.path.join(saved_models_dir, "model_comparison.json")

    print(f"[*] Saving best model to: {model_save_path}")
    joblib.dump(best_model_obj, model_save_path)

    # Also save to backend saved_models directory to keep runtime synchronized
    backend_save_path = os.path.join(base_dir, "..", "backend", "ml", "saved_models", "rf_model.joblib")
    if os.path.exists(os.path.dirname(backend_save_path)):
        joblib.dump(best_model_obj, backend_save_path)
        print(f"[+] Synchronized runtime model at: {backend_save_path}")

    print(f"[*] Saving feature column order to: {features_save_path}")
    with open(features_save_path, "w") as f:
        json.dump({
            "feature_columns": FEATURE_COLUMNS,
            "feature_count": len(FEATURE_COLUMNS),
            "target_mapping": {0: "Legitimate", 1: "Phishing"},
        }, f, indent=2)

    # Serialize benchmark summary
    serializable_summary = {
        "dataset_samples": len(raw_df),
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "feature_count": len(FEATURE_COLUMNS),
        "selected_model": best_model_name,
        "models": {
            name: {
                "accuracy": m["accuracy"],
                "precision": m["precision"],
                "recall": m["recall"],
                "f1_score": m["f1_score"],
                "roc_auc": m["roc_auc"],
                "confusion_matrix": m["confusion_matrix"],
            }
            for name, m in results.items()
        }
    }

    with open(comparison_save_path, "w") as f:
        json.dump(serializable_summary, f, indent=2)

    print(f"[+] Saved comparison metrics to: {comparison_save_path}")

    # 7. Cybersecurity Reality Caveat
    print("\n" + "=" * 70)
    print("            CYBERSECURITY DISCLAIMER & PRODUCTION REALITY             ")
    print("=" * 70)
    print(
        "IMPORTANT CAVEAT FOR EVALUATORS AND SECURITY ANALYSTS:\n"
        "- High test set accuracy on benchmark/synthetic datasets demonstrates that the\n"
        "  classifier effectively learned the structural boundaries of the training samples.\n"
        "- However, this DOES NOT imply the system is universally reliable or immune to\n"
        "  adversarial evasion in production.\n"
        "- Attackers continually adapt their tactics via concept drift, fast-flux DNS,\n"
        "  novel obfuscation tokens, and zero-day legitimate domain compromises.\n"
        "- Real-world systems must apply defense-in-depth: combine ML risk scores with\n"
        "  domain age, SSL certificate chain inspection, dynamic sandboxing, and user education."
    )
    print("=" * 70 + "\n")


if __name__ == "__main__":
    train_and_evaluate_pipeline()
