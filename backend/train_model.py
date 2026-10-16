"""
ScamShield Model Training, Validation, and Multi-Dataset Evaluation Engine
Includes:
- Stratified Train / Validation / Test split
- Candidate model comparison (Naive Bayes vs Balanced Logistic Regression)
- Operating threshold optimization on validation data
- Evaluation on primary held-out test split
- Independent external evaluation on modern Smishing and India-specific scam benchmarks
- Metrics serialization to model_metrics.json
"""

import os
import json
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


# ==================================================
# 1. PROJECT PATHS
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR = os.path.join(BASE_DIR, "model")

PRIMARY_DATA_PATH = os.path.join(DATA_DIR, "spam.csv")
CLEAN_DATA_PATH = os.path.join(DATA_DIR, "cleaned_spam.csv")
SCAM_BENCHMARK_PATH = os.path.join(DATA_DIR, "scam_benchmark.csv")
INDIA_BENCHMARK_PATH = os.path.join(DATA_DIR, "india_scam_benchmark.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "spam_pipeline.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")
CONFUSION_MATRIX_PATH = os.path.join(BASE_DIR, "confusion_matrix.png")

os.makedirs(MODEL_DIR, exist_ok=True)


# ==================================================
# 2. LOAD AND CLEAN PRIMARY DATASET
# ==================================================

print("\n==============================================")
print(" 1. LOADING PRIMARY DATASET")
print("==============================================")

if not os.path.exists(PRIMARY_DATA_PATH):
    raise FileNotFoundError(f"Primary dataset not found at: {PRIMARY_DATA_PATH}")

df = pd.read_csv(PRIMARY_DATA_PATH, encoding="cp1252")
print("Raw dataset dimensions:", df.shape)

# Combine split message columns
msg_cols = [c for c in df.columns if c != "v1"]
df["message"] = df[msg_cols].fillna("").astype(str).agg(" ".join, axis=1)
df["message"] = df["message"].str.replace(r"\s+", " ", regex=True).str.strip()
df["label"] = df["v1"].astype(str).str.strip().str.lower()

# Filter valid labels
df = df[df["label"].isin(["ham", "spam"])].copy()
df = df[df["message"].str.len() > 0].copy()

# Deduplicate
df = df.drop_duplicates(subset=["label", "message"]).reset_index(drop=True)
df[["label", "message"]].to_csv(CLEAN_DATA_PATH, index=False)

ham_count = int((df["label"] == "ham").sum())
spam_count = int((df["label"] == "spam").sum())

print(f"Cleaned dataset: {len(df)} total messages (Ham: {ham_count}, Spam: {spam_count})")


# ==================================================
# 3. SPLIT DATA: TRAIN (60%), VAL (20%), TEST (20%)
# ==================================================

X = df["message"]
y = df["label"]

X_trainval, X_test, y_trainval, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

X_train, X_val, y_train, y_val = train_test_split(
    X_trainval, y_trainval, test_size=0.25, random_state=42, stratify=y_trainval
)

print(f"Training samples:   {len(X_train)}")
print(f"Validation samples: {len(X_val)}")
print(f"Test samples:       {len(X_test)}")


# ==================================================
# 4. CANDIDATE PIPELINES
# ==================================================

def make_pipeline(clf):
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=30000,
            sublinear_tf=True
        )),
        ("classifier", clf)
    ])

candidate_models = {
    "Multinomial Naive Bayes": make_pipeline(MultinomialNB()),
    "Balanced Logistic Regression": make_pipeline(
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    )
}


# ==================================================
# 5. MODEL SELECTION ON VALIDATION SET
# ==================================================

print("\n==============================================")
print(" 2. MODEL SELECTION ON VALIDATION SET")
print("==============================================")

val_results = {}
for name, pipe in candidate_models.items():
    pipe.fit(X_train, y_train)
    val_preds = pipe.predict(X_val)
    val_rep = classification_report(
        y_val, val_preds, labels=["ham", "spam"], output_dict=True, zero_division=0
    )
    val_results[name] = {
        "accuracy": accuracy_score(y_val, val_preds),
        "precision": val_rep["spam"]["precision"],
        "recall": val_rep["spam"]["recall"],
        "f1": val_rep["spam"]["f1-score"]
    }
    print(f"\nModel: {name}")
    print(f"  Val Accuracy:  {val_results[name]['accuracy'] * 100:.2f}%")
    print(f"  Spam Recall:   {val_results[name]['recall'] * 100:.2f}%")
    print(f"  Spam F1-Score: {val_results[name]['f1'] * 100:.2f}%")

best_model_name = max(val_results, key=lambda m: val_results[m]["f1"])
print(f"\n>>> Selected Candidate: {best_model_name}")

selected_pipeline = candidate_models[best_model_name]


# ==================================================
# 6. OPERATING THRESHOLD INVESTIGATION
# ==================================================

print("\n==============================================")
print(" 3. OPERATING THRESHOLD INVESTIGATION (VAL SET)")
print("==============================================")

# Investigate classification thresholds using validation probabilities
classes = list(selected_pipeline.classes_)
spam_idx = classes.index("spam")
val_probs = selected_pipeline.predict_proba(X_val)[:, spam_idx]
y_val_binary = (y_val == "spam").astype(int)

candidate_thresholds = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
best_thresh = 0.5
best_thresh_f1 = 0.0
threshold_eval_table = []

for t in candidate_thresholds:
    preds_t = (val_probs >= t).astype(int)
    p = precision_score(y_val_binary, preds_t, zero_division=0)
    r = recall_score(y_val_binary, preds_t, zero_division=0)
    f = f1_score(y_val_binary, preds_t, zero_division=0)
    threshold_eval_table.append({
        "threshold": t,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f, 4)
    })
    print(f"  Threshold {t:.1f} -> Precision: {p:.3f}, Recall: {r:.3f}, F1: {f:.3f}")
    if f > best_thresh_f1:
        best_thresh_f1 = f
        best_thresh = t

print(f"\n>>> Chosen Operating Threshold: {best_thresh} (Validation F1: {best_thresh_f1:.4f})")


# ==================================================
# 7. FINAL MODEL FIT (TRAIN + VAL)
# ==================================================

X_full_train = pd.concat([X_train, X_val], ignore_index=True)
y_full_train = pd.concat([y_train, y_val], ignore_index=True)

selected_pipeline.fit(X_full_train, y_full_train)


# ==================================================
# 8. EVALUATION ON PRIMARY TEST SET
# ==================================================

print("\n==============================================")
print(" 4. EVALUATION ON HELD-OUT PRIMARY TEST SET")
print("==============================================")

test_probs = selected_pipeline.predict_proba(X_test)[:, spam_idx]
test_preds = np.where(test_probs >= best_thresh, "spam", "ham")

acc = accuracy_score(y_test, test_preds)
report = classification_report(
    y_test, test_preds, labels=["ham", "spam"], output_dict=True, zero_division=0
)
cm = confusion_matrix(y_test, test_preds, labels=["ham", "spam"])

print(f"Test Accuracy:  {acc * 100:.2f}%")
print(f"Spam Precision: {report['spam']['precision'] * 100:.2f}%")
print(f"Spam Recall:    {report['spam']['recall'] * 100:.2f}%")
print(f"Spam F1-Score:  {report['spam']['f1-score'] * 100:.2f}%")
print("\nConfusion Matrix (Ham, Spam):")
print(cm)


# Save confusion matrix plot
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Ham", "Spam"])
disp.plot(values_format="d", cmap="Blues")
plt.title(f"ScamShield Evaluation - {best_model_name}")
plt.tight_layout()
plt.savefig(CONFUSION_MATRIX_PATH, dpi=150)
plt.close()


# ==================================================
# 9. EVALUATION ON EXTERNAL INDEPENDENT BENCHMARKS
# ==================================================

print("\n==============================================")
print(" 5. EVALUATION ON EXTERNAL INDEPENDENT BENCHMARKS")
print("==============================================")

def evaluate_external_dataset(csv_path, dataset_name):
    if not os.path.exists(csv_path):
        print(f"Warning: {csv_path} not found.")
        return None
    
    df_ext = pd.read_csv(csv_path)
    ext_msgs = df_ext["message"]
    ext_labels = df_ext["label"]
    
    ext_probs = selected_pipeline.predict_proba(ext_msgs)[:, spam_idx]
    ext_preds = np.where(ext_probs >= best_thresh, "spam", "ham")
    
    ext_acc = accuracy_score(ext_labels, ext_preds)
    ext_rep = classification_report(
        ext_labels, ext_preds, labels=["ham", "spam"], output_dict=True, zero_division=0
    )
    ext_cm = confusion_matrix(ext_labels, ext_preds, labels=["ham", "spam"])
    
    print(f"\n--- {dataset_name} ({len(df_ext)} samples) ---")
    print(f"  Accuracy:       {ext_acc * 100:.2f}%")
    print(f"  Spam Recall:    {ext_rep['spam']['recall'] * 100:.2f}%")
    print(f"  Spam Precision: {ext_rep['spam']['precision'] * 100:.2f}%")
    print(f"  Spam F1-Score:  {ext_rep['spam']['f1-score'] * 100:.2f}%")
    
    return {
        "dataset_name": dataset_name,
        "sample_count": len(df_ext),
        "accuracy": round(float(ext_acc), 4),
        "spam_precision": round(float(ext_rep["spam"]["precision"]), 4),
        "spam_recall": round(float(ext_rep["spam"]["recall"]), 4),
        "spam_f1": round(float(ext_rep["spam"]["f1-score"]), 4),
        "confusion_matrix": {
            "labels": ["Ham", "Spam"],
            "values": ext_cm.tolist()
        }
    }

scam_bench_eval = evaluate_external_dataset(SCAM_BENCHMARK_PATH, "Independent Smishing Benchmark")
india_bench_eval = evaluate_external_dataset(INDIA_BENCHMARK_PATH, "India Social Engineering Benchmark")


# ==================================================
# 10. SAVE ARTIFACTS AND METRICS JSON
# ==================================================

# Save pipeline
joblib.dump(selected_pipeline, MODEL_PATH)

metrics_payload = {
    "selected_model": best_model_name,
    "classification_threshold": best_thresh,
    "evaluation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "dataset_info": {
        "total_cleaned_samples": len(df),
        "ham_samples": ham_count,
        "spam_samples": spam_count,
        "training_samples": len(X_full_train),
        "test_samples": len(y_test)
    },
    "test_split_metrics": {
        "accuracy": round(float(acc), 4),
        "spam_precision": round(float(report["spam"]["precision"]), 4),
        "spam_recall": round(float(report["spam"]["recall"]), 4),
        "spam_f1": round(float(report["spam"]["f1-score"]), 4),
        "test_samples": int(len(y_test)),
        "confusion_matrix": {
            "labels": ["Ham", "Spam"],
            "values": cm.tolist()
        }
    },
    "threshold_tuning": threshold_eval_table,
    "external_benchmarks": {
        "smishing_benchmark": scam_bench_eval,
        "india_social_engineering": india_bench_eval
    },
    # Backwards-compatible root keys for legacy consumers
    "accuracy": round(float(acc), 4),
    "spam_precision": round(float(report["spam"]["precision"]), 4),
    "spam_recall": round(float(report["spam"]["recall"]), 4),
    "spam_f1": round(float(report["spam"]["f1-score"]), 4),
    "test_samples": int(len(y_test)),
    "confusion_matrix": {
        "labels": ["Ham", "Spam"],
        "values": cm.tolist()
    }
}

with open(METRICS_PATH, "w", encoding="utf-8") as f:
    json.dump(metrics_payload, f, indent=4)

print(f"\n>>> Model saved to: {MODEL_PATH}")
print(f">>> Metrics saved to: {METRICS_PATH}")
print(f">>> Confusion Matrix plot saved to: {CONFUSION_MATRIX_PATH}")
print("\nScamShield training and multi-benchmark evaluation completed successfully!")