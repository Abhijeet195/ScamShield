import os
import json

import joblib

from flask import Flask, request, jsonify
from flask_cors import CORS


# ==================================================
# 1. INITIALIZE FLASK APPLICATION
# ==================================================

app = Flask(__name__)

# Allow requests from the React development server.
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173"
            ]
        }
    }
)


# ==================================================
# 2. DEFINE FILE PATHS
# ==================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "spam_pipeline.joblib"
)

METRICS_PATH = os.path.join(
    BASE_DIR,
    "model",
    "model_metrics.json"
)


# ==================================================
# 3. LOAD TRAINED MACHINE-LEARNING MODEL
# ==================================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        "Trained model not found. "
        "Run train_model.py first."
    )

model = joblib.load(MODEL_PATH)

print("ScamShield model loaded successfully!")


# ==================================================
# 4. HEALTH CHECK API
# ==================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "success",
        "message": "ScamShield API is running."
    })


# ==================================================
# 5. MODEL PERFORMANCE METRICS API
# ==================================================

@app.route("/api/metrics", methods=["GET"])
def get_metrics():

    if not os.path.exists(METRICS_PATH):
        return jsonify({
            "error": (
                "Model metrics file not found. "
                "Run train_model.py first."
            )
        }), 404

    try:
        with open(
            METRICS_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            metrics = json.load(file)

        return jsonify(metrics)

    except (OSError, json.JSONDecodeError):

        return jsonify({
            "error": "Unable to load model metrics."
        }), 500


# ==================================================
# 6. MESSAGE CLASSIFICATION API
# ==================================================

@app.route("/api/predict", methods=["POST"])
def predict():

    data = request.get_json(silent=True)

    # Validate the incoming request.

    if not isinstance(data, dict):
        return jsonify({
            "error": "A valid JSON request is required."
        }), 400

    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({
            "error": "Message must be text."
        }), 400

    message = message.strip()

    if not message:
        return jsonify({
            "error": "Please enter a message."
        }), 400

    if len(message) > 5000:
        return jsonify({
            "error": "Message cannot exceed 5000 characters."
        }), 400

    # Generate the model prediction.

    prediction = model.predict([message])[0]

    # Calculate estimated class probabilities.

    probabilities = model.predict_proba([message])[0]

    classes = list(model.classes_)

    spam_index = classes.index("spam")

    spam_probability = float(
        probabilities[spam_index]
    )

    # Prepare the response.

    if prediction == "spam":

        result = {
            "prediction": "spam",
            "label": "Potentially Suspicious",
            "warning": (
                "The model classified this message as spam. "
                "Be cautious and independently verify the "
                "message before clicking links or sharing "
                "sensitive information."
            )
        }

    else:

        result = {
            "prediction": "ham",
            "label": "Not Flagged as Spam",
            "warning": (
                "The model did not flag this message as spam. "
                "This does not guarantee that the message is safe."
            )
        }

    result["spam_probability"] = round(
        spam_probability * 100,
        2
    )

    return jsonify(result)


# ==================================================
# 7. RUN THE DEVELOPMENT SERVER
# ==================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )