"""
ScamShield Transparent Risk Assessment Engine
Combines Machine Learning model score, Explainable Scam Indicators, and URL Risk Analysis
to produce an objective, transparent assessment category and contextual guidance.
"""

from typing import Dict, Any, List


def evaluate_risk(
    model_score: float,
    scam_data: Dict[str, Any],
    url_data: Dict[str, Any],
    text: str
) -> Dict[str, Any]:
    """
    Synthesize all available signals into an assessment category, composite risk score,
    and contextual safety recommendations.

    Args:
        model_score: Classifier probability of spam (0.0 to 1.0)
        scam_data: Dictionary returned by scam_analyzer.analyze_scam_indicators
        url_data: Dictionary returned by url_analyzer.analyze_urls_in_text
        text: Raw message content
    """
    indicators = scam_data.get("indicators", [])
    indicator_count = len(indicators)
    highest_indicator_sev = scam_data.get("highest_severity", "none")
    
    url_risk = url_data.get("max_risk_level", "none")
    has_url = url_data.get("has_url", False)
    
    # Calculate transparent composite risk score (0 to 100)
    # ML model contributes up to 45 points
    ml_component = min(45.0, model_score * 45.0)
    
    # URL risk contributes up to 30 points
    url_component = 0.0
    if url_risk == "high":
        url_component = 30.0
    elif url_risk == "medium":
        url_component = 18.0
    elif has_url:
        url_component = 8.0
        
    # Scam indicator rules contribute up to 35 points
    indicator_component = 0.0
    high_sev_count = sum(1 for i in indicators if i.get("severity") == "high")
    med_sev_count = sum(1 for i in indicators if i.get("severity") == "medium")
    
    indicator_component += min(25.0, high_sev_count * 15.0)
    indicator_component += min(10.0, med_sev_count * 6.0)
    
    raw_composite = ml_component + url_component + indicator_component
    composite_score = round(min(100.0, raw_composite), 1)
    
    # Determine Assessment Category
    # Criteria for 'High Concern':
    # 1. High-risk URL detected AND any high severity indicator or model_score >= 0.40
    # 2. At least two high-severity scam indicators (e.g. Urgency + OTP, KYC + Urgency)
    # 3. Model score >= 0.85 AND at least one indicator
    # 4. Composite score >= 60.0
    if (
        (url_risk == "high" and (high_sev_count >= 1 or model_score >= 0.40))
        or high_sev_count >= 2
        or (model_score >= 0.85 and (indicator_count >= 1 or has_url))
        or composite_score >= 60.0
    ):
        category = "High Concern"
        category_description = (
            "Multiple concerning indicators detected. The message exhibits strong "
            "characteristics of fraudulent social engineering or deceptive links."
        )
        badge_style = "danger"
        
    elif (
        composite_score >= 25.0
        or high_sev_count >= 1
        or med_sev_count >= 1
        or url_risk == "medium"
        or model_score >= 0.45
    ):
        category = "Needs Review"
        category_description = (
            "Suspicious indicators or elevated model score detected. Evidence is inconclusive "
            "and requires manual verification before taking any action."
        )
        badge_style = "warning"
        
    else:
        category = "No Clear Spam Indicators"
        category_description = (
            "The automated checks did not find sufficient indicators to flag this message. "
            "However, safety cannot be unconditionally guaranteed."
        )
        badge_style = "safe"

    # Generate Tailored Safety Recommendations
    recommendations: List[str] = []
    
    # Context-specific guidance based on detected indicators
    detected_ids = {i["id"] for i in indicators}
    
    if "otp_request" in detected_ids:
        recommendations.append(
            "Never share an OTP, PIN, or verification code. Genuine banks and institutions "
            "will never call or text asking you to disclose your OTP."
        )
        
    if "upi_payment_trap" in detected_ids:
        recommendations.append(
            "Critical UPI Rule: You never enter your UPI PIN or scan a QR code to receive money. "
            "Entering a PIN always deducts money from your account."
        )
        
    if "kyc_suspension" in detected_ids or "brand_impersonation" in detected_ids:
        recommendations.append(
            "Do not use links in messages to update KYC, PAN, or account details. Always open "
            "your bank's official mobile application or verified website directly."
        )
        
    if "utility_disconnection" in detected_ids:
        recommendations.append(
            "Electricity boards do not disconnect power over SMS without official registered notice. "
            "Verify your bill status directly via the state electricity portal or consumer helpline."
        )
        
    if "prize_lottery" in detected_ids or "job_task_scam" in detected_ids:
        recommendations.append(
            "Be skeptical of unexpected lottery prizes or work-from-home offers demanding advance "
            "registration fees or Telegram group tasks."
        )
        
    if has_url:
        if url_risk == "high":
            recommendations.append(
                "Do NOT click or open the link provided in the message. The URL exhibits "
                "evasion techniques (shortener, IP address, or high-risk domain)."
            )
        else:
            recommendations.append(
                "Inspect any embedded link independently before navigating. Check the exact domain "
                "name rather than relying on visible link text."
            )
            
    # Always provide official reporting helpline for users
    recommendations.append(
        "If you suspect financial cyber fraud, report it immediately on cybercrime.gov.in "
        "or call India's National Cyber Fraud Helpline at 1930."
    )

    return {
        "assessment_category": category,
        "category_description": category_description,
        "badge_style": badge_style,
        "composite_risk_score": composite_score,
        "score_breakdown": {
            "ml_model_contribution": round(ml_component, 1),
            "url_analysis_contribution": round(url_component, 1),
            "indicators_contribution": round(indicator_component, 1)
        },
        "recommendations": recommendations
    }
