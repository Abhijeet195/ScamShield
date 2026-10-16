"""
ScamShield Explainable Scam Analysis Engine
Identifies deceptive patterns, social engineering lures, and manipulative language
with transparent indicator explanations, matched evidence snippets, and severity ratings.
"""

import re
from typing import List, Dict, Any


# Pre-compiled indicator patterns with regex, category, severity, and rationale
INDICATOR_RULES = [
    {
        "id": "urgency_coercion",
        "category": "Urgency & Psychological Pressure",
        "title": "Artificial Urgency or Account Threat",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:immediate(?:ly)?|urgent(?:ly)?|suspend(?:ed)?|block(?:ed)?|disconnect(?:ed)?|deactivat(?:ed|ion)|'
            r'within\s+(?:\d+|twenty-four|24|12|48)\s*hours?|today\b|tonight\b|last\s+(?:day|chance|warning)|'
            r'action\s+required|penalty|fine\s+of|legal\s+action)\b',
            re.IGNORECASE
        ),
        "explanation": "Scammers manufacture extreme urgency or threaten account deactivation to pressure victims into acting without thinking."
    },
    {
        "id": "otp_request",
        "category": "Credential & Secret Disclosure",
        "title": "Request for OTP or Security Code",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:share\s+otp|send\s+(?:the\s+)?otp|enter\s+otp|provide\s+(?:the\s+)?(?:otp|code|pin)|'
            r'one-time\s+password|verification\s+code\s+is\s+required|share\s+the\s+code)\b',
            re.IGNORECASE
        ),
        "explanation": "Legitimate banks and services never ask users to share their One-Time Password (OTP) or security PIN over messages."
    },
    {
        "id": "credential_harvesting",
        "category": "Credential & Secret Disclosure",
        "title": "Credential or Identity Harvesting",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:enter\s+(?:your\s+)?(?:password|pin|mpin|credentials|login\s+details)|'
            r'verify\s+(?:your\s+)?(?:password|identity|netbanking|account\s+details)|'
            r'submit\s+(?:your\s+)?(?:card\s+number|cvv|expiry))\b',
            re.IGNORECASE
        ),
        "explanation": "Direct requests to enter login passwords, MPINs, or card CVVs via an unverified link or chat."
    },
    {
        "id": "kyc_suspension",
        "category": "Identity & Compliance Lures",
        "title": "Fake KYC / Identity Update Threat",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:(?:kyc|pan|aadhaar|sim)\s+(?:update|pending|suspended|expired|verification|link|block)|'
            r'(?:update|pending|expired|suspended|verify|link)\s+(?:kyc|pan|aadhaar|sim|pan\s+card)|'
            r'pan\s+card\s+(?:link|block|update|suspended)|'
            r'sim\s+(?:block|deactivat(?:ed|ion)|verification))\b',
            re.IGNORECASE
        ),
        "explanation": "Threats claiming that banking or SIM services will stop unless an immediate KYC/PAN verification is performed."
    },
    {
        "id": "upi_payment_trap",
        "category": "Financial Social Engineering",
        "title": "UPI / Payment PIN Social Engineering",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:enter\s+upi\s+pin\s+to\s+receive|scan\s+(?:this\s+)?qr\s+to\s+receive|'
            r'receive\s+money\s+enter\s+pin|upi\s+cashback\s+claim|refund\s+approval\s+enter\s+pin)\b',
            re.IGNORECASE
        ),
        "explanation": "A critical fraud technique: entering a UPI PIN always deducts money from your account; you never enter a PIN to receive funds."
    },
    {
        "id": "prize_lottery",
        "category": "Unsolicited Reward & Lottery",
        "title": "Unsolicited Prize, Lottery, or Reward Claim",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:won\s+(?:a\s+)?(?:lottery|cash\s+prize|car|iphone|reward|\$\d+|rs\.?\s*\d+|crore|lakh)|'
            r'congratulations\s+you\s+(?:have\s+)?won|lucky\s+draw\s+winner|kbc\s+lottery|claim\s+your\s+prize|'
            r'exclusive\s+gift\s+voucher)\b',
            re.IGNORECASE
        ),
        "explanation": "Bogus lottery winnings, cashback offers, and surprise prizes designed to entice victims into paying advance fees or sharing details."
    },
    {
        "id": "utility_disconnection",
        "category": "Financial Social Engineering",
        "title": "Utility / Electricity Disconnection Lure",
        "severity": "high",
        "regex": re.compile(
            r'\b(?:electricity\s+(?:power\s+)?(?:will\s+be\s+)?disconnect(?:ed)?|'
            r'power\s+cut(?:-off)?\s+(?:tonight|today)|previous\s+month\s+bill\s+not\s+updated|'
            r'contact\s+(?:our\s+)?(?:electricity|power)\s+officer)\b',
            re.IGNORECASE
        ),
        "explanation": "Widespread smishing lure alleging immediate power shutoff over an unpaid bill, urging payment to a personal number or link."
    },
    {
        "id": "job_task_scam",
        "category": "Employment & Work From Home Lures",
        "title": "Part-Time Task or Unrealistic Job Offer",
        "severity": "medium",
        "regex": re.compile(
            r'\b(?:part-?time\s+job|work\s+from\s+home\s+earn|earn\s+daily\s+(?:rs\.?|\$)\s*\d+|'
            r'youtube\s+like\s+and\s+earn|telegram\s+task|simple\s+daily\s+tasks?\s+earn|no\s+experience\s+needed\s+daily\s+pay)\b',
            re.IGNORECASE
        ),
        "explanation": "Offers of high daily returns for simple online tasks (like liking videos or leaving reviews), usually escalating into Telegram prepay scams."
    },
    {
        "id": "courier_parcel_scam",
        "category": "Delivery & Logistics Lures",
        "title": "Failed Parcel Delivery / Address Update",
        "severity": "medium",
        "regex": re.compile(
            r'\b(?:package|parcel|shipment|delivery)\s+(?:cannot\s+be\s+delivered|on\s+hold|address\s+missing|incomplete\s+address|reschedule\s+delivery)\b',
            re.IGNORECASE
        ),
        "explanation": "Phishing lure impersonating India Post, FedEx, or courier services claiming a delivery failed and demanding an address update or small fee."
    },
    {
        "id": "brand_impersonation",
        "category": "Brand & Authority Impersonation",
        "title": "Organization / Financial Institution Impersonation",
        "severity": "medium",
        "regex": re.compile(
            r'\b(?:sbi|yono|hdfc|icici|axis\s+bank|pnb|paytm|phonepe|google\s+pay|gpay|'
            r'income\s+tax\s+department|india\s+post|trai|cbi|rbi|cyber\s+crime\s+department)\b',
            re.IGNORECASE
        ),
        "explanation": "Mention of a reputable bank, government agency, or digital wallet provider. Frequently used to establish false trust."
    }
]


def extract_evidence(text: str, regex: re.Pattern) -> str:
    """Find the specific substring in the message that triggered the pattern."""
    match = regex.search(text)
    if not match:
        return ""
    start, end = match.span()
    # Provide surrounding context (up to 30 characters on each side)
    snippet_start = max(0, start - 20)
    snippet_end = min(len(text), end + 20)
    prefix = "..." if snippet_start > 0 else ""
    suffix = "..." if snippet_end < len(text) else ""
    return f"{prefix}{text[snippet_start:snippet_end].strip()}{suffix}"


def analyze_scam_indicators(text: str) -> Dict[str, Any]:
    """
    Examine the message against defined scam and social engineering indicators.
    Returns detected indicators, categories, matched evidence, and severity breakdown.
    """
    if not text or not isinstance(text, str):
        return {
            "indicator_count": 0,
            "indicators": [],
            "categories_found": [],
            "highest_severity": "none"
        }

    detected_indicators: List[Dict[str, Any]] = []
    categories_found = set()
    severities = set()

    for rule in INDICATOR_RULES:
        if rule["regex"].search(text):
            evidence = extract_evidence(text, rule["regex"])
            detected_indicators.append({
                "id": rule["id"],
                "title": rule["title"],
                "category": rule["category"],
                "severity": rule["severity"],
                "evidence": evidence,
                "explanation": rule["explanation"]
            })
            categories_found.add(rule["category"])
            severities.add(rule["severity"])

    highest_severity = "none"
    if "high" in severities:
        highest_severity = "high"
    elif "medium" in severities:
        highest_severity = "medium"
    elif "low" in severities:
        highest_severity = "low"

    return {
        "indicator_count": len(detected_indicators),
        "indicators": detected_indicators,
        "categories_found": sorted(list(categories_found)),
        "highest_severity": highest_severity
    }
