"""
ScamShield Backend API
Flask server providing explainable scam analysis, machine-learning classification,
URL risk inspection, model performance metrics, and pre-click verification.
Privacy-conscious: No user message content is logged or persisted to disk.
"""

import os
import json
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

from url_analyzer import analyze_urls_in_text, analyze_single_url
from scam_analyzer import analyze_scam_indicators
from risk_assessment import evaluate_risk


# ==================================================
# 1. INITIALIZE FLASK APPLICATION & CORS
# ==================================================

app = Flask(__name__)

# Allow requests from React frontend and browser extensions
allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "SCAMSHIELD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": allowed_origins
        }
    }
)


# ==================================================
# 2. PATHS AND MODEL LOADING
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "spam_pipeline.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "model", "model_metrics.json")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Trained model not found at {MODEL_PATH}. Run train_model.py first."
    )

model = joblib.load(MODEL_PATH)

# Load metrics and operating threshold
metrics_cache = None
operating_threshold = 0.6  # Default fallback

if os.path.exists(METRICS_PATH):
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics_cache = json.load(f)
            operating_threshold = metrics_cache.get("classification_threshold", 0.6)
    except Exception as e:
        print(f"Warning: could not parse {METRICS_PATH}: {e}")

classes = list(model.classes_)
spam_index = classes.index("spam") if "spam" in classes else 1

print(f"ScamShield model loaded successfully! (Operating Threshold: {operating_threshold})")


# ==================================================
# 3. HEALTH CHECK API
# ==================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "service": "ScamShield API",
        "version": "2.0.0",
        "model_loaded": True
    })


# ==================================================
# 4. MODEL PERFORMANCE METRICS API
# ==================================================

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    if not os.path.exists(METRICS_PATH):
        return jsonify({
            "error": "Model metrics file not found. Run train_model.py first."
        }), 404

    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics = json.load(f)
        return jsonify(metrics)
    except (OSError, json.JSONDecodeError):
        return jsonify({
            "error": "Unable to load model metrics."
        }), 500


# ==================================================
# 5. PRE-CLICK URL RISK CHECK API
# ==================================================

@app.route("/api/url-check", methods=["POST"])
def check_url():
    """
    Dedicated endpoint for inspecting URLs prior to navigation.
    Used by the React Pre-Click simulation and Chrome extension.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON request is required."}), 400

    url_str = data.get("url", "")
    if not isinstance(url_str, str) or not url_str.strip():
        return jsonify({"error": "Please provide a valid URL to inspect."}), 400

    url_str = url_str.strip()
    analysis = analyze_single_url(url_str)
    
    # Assess pre-click navigation advisory
    is_dangerous = analysis["risk_level"] == "high"
    is_suspicious = analysis["risk_level"] == "medium"
    
    if is_dangerous:
        action = "BLOCK_RECOMMENDED"
        guidance = "High-risk URL patterns detected. We strongly advise against visiting this link."
    elif is_suspicious:
        action = "CAUTION_REQUIRED"
        guidance = "URL exhibits obfuscation or shortening. Inspect verified destination before proceeding."
    else:
        action = "STANDARD_CAUTION"
        guidance = "Standard URL structure. Ensure you recognize the destination domain."

    return jsonify({
        "url": url_str,
        "action": action,
        "risk_level": analysis["risk_level"],
        "guidance": guidance,
        "details": analysis
    })


# ==================================================
# 6. EXPLAINABLE MESSAGE PREDICTION & ANALYSIS API
# ==================================================

@app.route("/api/predict", methods=["POST"])
@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Complete analysis pipeline:
    1. Input validation & sanitization
    2. ML probability estimation
    3. Explainable indicator detection
    4. Safe URL inspection
    5. Multi-signal transparent risk assessment
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON request is required."}), 400

    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    message = message.strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    if len(message) > 5000:
        return jsonify({"error": "Message cannot exceed 5000 characters."}), 400

    # 1. Machine Learning Probability
    probabilities = model.predict_proba([message])[0]
    spam_prob = float(probabilities[spam_index])
    
    # Apply calibrated validation threshold
    ml_prediction = "spam" if spam_prob >= operating_threshold else "ham"

    # 2. Explainable Scam Indicator Analysis
    scam_data = analyze_scam_indicators(message)

    # 3. URL Risk Analysis
    url_data = analyze_urls_in_text(message)

    # 4. Multi-Signal Transparent Risk Assessment
    risk_data = evaluate_risk(spam_prob, scam_data, url_data, message)

    # Formulate primary user-facing label and warning
    assessment_cat = risk_data["assessment_category"]
    
    if assessment_cat == "High Concern":
        label = "High Risk / Potentially Fraudulent"
        warning = (
            "ScamShield detected multiple concerning indicators. This message exhibits "
            "strong patterns of fraudulent social engineering or deceptive links. "
            "Do NOT click any links, share OTPs, or send money."
        )
    elif assessment_cat == "Needs Review":
        label = "Suspicious / Needs Review"
        warning = (
            "This message contains suspicious indicators or an elevated risk score. "
            "Exercise caution and independently verify the sender's identity through "
            "official channels before taking any action."
        )
    else:
        label = "No Clear Spam Indicators"
        warning = (
            "The model and indicator rules did not detect overt spam patterns in this text. "
            "Note: This does not guarantee safety. Always verify sensitive requests independently."
        )

    response_payload = {
        "prediction": ml_prediction,
        "label": label,
        "warning": warning,
        "spam_probability": round(spam_prob * 100, 2),
        "operating_threshold": operating_threshold,
        "assessment": {
            "category": risk_data["assessment_category"],
            "description": risk_data["category_description"],
            "badge_style": risk_data["badge_style"],
            "composite_risk_score": risk_data["composite_risk_score"],
            "score_breakdown": risk_data["score_breakdown"],
            "recommendations": risk_data["recommendations"]
        },
        "indicators": scam_data["indicators"],
        "indicator_count": scam_data["indicator_count"],
        "url_analysis": url_data
    }

    return jsonify(response_payload)


# ==================================================
# 7. RUN DEVELOPMENT SERVER
# ==================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    debug_mode = os.environ.get("FLASK_ENV") == "development"

    print(f"Starting ScamShield API on http://{host}:{port}")
    app.run(
        host=host,
        port=port,
        debug=debug_mode
    )