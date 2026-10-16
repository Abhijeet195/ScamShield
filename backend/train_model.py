import os
import json

import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

# ==================================================
# 1. PROJECT PATHS
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_PATH = os.path.join(
    BASE_DIR, "dataset", "spam.csv"
)

CLEAN_DATA_PATH = os.path.join(
    BASE_DIR, "dataset", "cleaned_spam.csv"
)

MODEL_DIR = os.path.join(BASE_DIR, "model")

MODEL_PATH = os.path.join(
    MODEL_DIR, "spam_pipeline.joblib"
)

METRICS_PATH = os.path.join(
    MODEL_DIR, "model_metrics.json"
)

CONFUSION_MATRIX_PATH = os.path.join(
    BASE_DIR, "confusion_matrix.png"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# ==================================================
# 2. LOAD DATASET
# ==================================================

print("\nLoading dataset...")

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        f"Dataset not found at: {DATA_PATH}"
    )

df = pd.read_csv(
    DATA_PATH,
    encoding="cp1252"
)

print("Original dataset shape:", df.shape)
print("Dataset columns:", df.columns.tolist())

if "v1" not in df.columns:
    raise ValueError(
        "Label column 'v1' was not found in the dataset."
    )


# ==================================================
# 3. CLEAN AND PREPARE DATA
# ==================================================

# Combine all message columns to preserve
# messages that have been split across columns.

message_columns = [
    column for column in df.columns
    if column != "v1"
]

df["message"] = (
    df[message_columns]
    .fillna("")
    .astype(str)
    .agg(" ".join, axis=1)
)

# Remove unnecessary whitespace.

df["message"] = (
    df["message"]
    .str.replace(r"\s+", " ", regex=True)
    .str.strip()
)

# Standardize class labels.

df["label"] = (
    df["v1"]
    .astype(str)
    .str.strip()
    .str.lower()
)

# Retain only the expected categories.

df = df[
    df["label"].isin(["ham", "spam"])
].copy()

# Remove empty messages.

df = df[
    df["message"].str.len() > 0
].copy()

# Remove duplicate message-label combinations.

df = df.drop_duplicates(
    subset=["label", "message"]
).reset_index(drop=True)

# Save a clean dataset containing only required columns.

df[["label", "message"]].to_csv(
    CLEAN_DATA_PATH,
    index=False
)

print("\nCleaned dataset shape:", df.shape)

print("\nClass distribution:")
print(df["label"].value_counts())


# ==================================================
# 4. SEPARATE FEATURES AND LABELS
# ==================================================

X = df["message"]
y = df["label"]


# ==================================================
# 5. CREATE TRAINING, VALIDATION AND TEST SETS
# ==================================================

# Reserve 20% for final testing.

X_trainval, X_test, y_trainval, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Split the remaining 80% into:
# 60% training and 20% validation of the full dataset.

X_train, X_val, y_train, y_val = train_test_split(
    X_trainval,
    y_trainval,
    test_size=0.25,
    random_state=42,
    stratify=y_trainval
)

print("\nTraining samples:", len(X_train))
print("Validation samples:", len(X_val))
print("Testing samples:", len(X_test))


# ==================================================
# 6. CREATE MODEL PIPELINE
# ==================================================

def create_pipeline(classifier):

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=30000,
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            classifier
        )
    ])


# ==================================================
# 7. DEFINE CANDIDATE MODELS
# ==================================================

models = {
    "Multinomial Naive Bayes": create_pipeline(
        MultinomialNB()
    ),

    "Balanced Logistic Regression": create_pipeline(
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=42
        )
    )
}


# ==================================================
# 8. TRAIN AND COMPARE MODELS
# ==================================================

print("\n========== MODEL COMPARISON ==========")

validation_results = {}

for name, model in models.items():

    print(f"\nTraining: {name}")

    model.fit(
        X_train,
        y_train
    )

    predictions = model.predict(X_val)

    report = classification_report(
        y_val,
        predictions,
        labels=["ham", "spam"],
        target_names=["Ham (not spam)", "Spam"],
        output_dict=True,
        zero_division=0
    )

    validation_results[name] = {
        "accuracy": accuracy_score(
            y_val, predictions
        ),
        "precision": report["Spam"]["precision"],
        "recall": report["Spam"]["recall"],
        "f1": report["Spam"]["f1-score"]
    }

    print(
        "Validation accuracy:",
        f"{validation_results[name]['accuracy'] * 100:.2f}%"
    )

    print(
        "Spam precision:",
        f"{validation_results[name]['precision']:.3f}"
    )

    print(
        "Spam recall:",
        f"{validation_results[name]['recall']:.3f}"
    )

    print(
        "Spam F1-score:",
        f"{validation_results[name]['f1']:.3f}"
    )


# Select the model with the highest spam F1-score
# on validation data.

best_name = max(
    validation_results,
    key=lambda name: validation_results[name]["f1"]
)

best_model = models[best_name]

print("\nSelected model:", best_name)


# ==================================================
# 9. RETRAIN USING TRAINING + VALIDATION DATA
# ==================================================

X_final_train = pd.concat(
    [X_train, X_val],
    ignore_index=True
)

y_final_train = pd.concat(
    [y_train, y_val],
    ignore_index=True
)

best_model.fit(
    X_final_train,
    y_final_train
)


# ==================================================
# 10. EVALUATE ON THE UNSEEN TEST SET
# ==================================================

test_predictions = best_model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    test_predictions
)

print("\n========== FINAL TEST RESULTS ==========")

print("Selected model:", best_name)

print(
    f"\nTest accuracy: {accuracy * 100:.2f}%"
)

# Generate detailed classification metrics.

report_data = classification_report(
    y_test,
    test_predictions,
    labels=["ham", "spam"],
    target_names=["Ham (not spam)", "Spam"],
    output_dict=True,
    zero_division=0
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        test_predictions,
        labels=["ham", "spam"],
        target_names=["Ham (not spam)", "Spam"],
        zero_division=0
    )
)


# ==================================================
# 11. GENERATE CONFUSION MATRIX
# ==================================================

cm = confusion_matrix(
    y_test,
    test_predictions,
    labels=["ham", "spam"]
)

print("Confusion Matrix:")
print(cm)

ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Ham", "Spam"]
).plot(values_format="d")

plt.title(f"ScamShield - {best_name}")
plt.tight_layout()

plt.savefig(
    CONFUSION_MATRIX_PATH,
    dpi=150
)

plt.close()


# ==================================================
# 12. PREPARE DASHBOARD METRICS
# ==================================================

metrics_data = {
    "selected_model": best_name,

    "accuracy": round(
        float(accuracy), 4
    ),

    "spam_precision": round(
        float(report_data["Spam"]["precision"]), 4
    ),

    "spam_recall": round(
        float(report_data["Spam"]["recall"]), 4
    ),

    "spam_f1": round(
        float(report_data["Spam"]["f1-score"]), 4
    ),

    "test_samples": int(len(y_test)),

    "confusion_matrix": {
        "labels": ["Ham", "Spam"],
        "values": cm.tolist()
    }
}


# ==================================================
# 13. SAVE MODEL AND METRICS
# ==================================================

joblib.dump(
    best_model,
    MODEL_PATH
)

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metrics_data,
        file,
        indent=4
    )

print("\nModel saved successfully:")
print(MODEL_PATH)

print("\nDashboard metrics saved successfully:")
print(METRICS_PATH)

print("\nConfusion matrix saved:")
print(CONFUSION_MATRIX_PATH)


# ==================================================
# 14. TEST SAMPLE PREDICTIONS
# ==================================================

test_messages = [
    "Congratulations! You have won a free prize. Click now!",
    "Hi, are we meeting at college tomorrow?"
]

print("\nSample Predictions:")

for message in test_messages:

    prediction = best_model.predict([message])[0]

    probabilities = best_model.predict_proba([message])[0]

    classes = list(best_model.classes_)

    spam_index = classes.index("spam")

    spam_probability = probabilities[spam_index] * 100

    print("\nMessage:", message)
    print("Prediction:", prediction)
    print(
        f"Estimated spam probability: {spam_probability:.2f}%"
    )

print("\nModel training and evaluation completed successfully!")