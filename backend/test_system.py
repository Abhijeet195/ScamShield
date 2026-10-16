"""
ScamShield Comprehensive Automated Test Suite
Validates application reliability, edge cases, indicator logic, URL inspection,
and model behavior across standard, adversarial, and region-specific test inputs.
"""

import time
import json
from app import app


def run_tests():
    client = app.test_client()
    passed = 0
    total = 0

    print("\n========================================================")
    print("      SCAMSHIELD 2.0 AUTOMATED TEST SUITE EXECUTION     ")
    print("========================================================")

    test_cases = [
        {
            "id": "TC-01",
            "name": "Ordinary Conversational Message",
            "payload": {"message": "Hey, are we still meeting for coffee tomorrow afternoon?"},
            "check": lambda res, data: res.status_code == 200 and data["assessment"]["category"] == "No Clear Spam Indicators",
            "expected": "No Clear Spam Indicators (no false alarm)"
        },
        {
            "id": "TC-02",
            "name": "Promotional Spam with Urgency",
            "payload": {"message": "Congratulations! You have been selected to win a free $1000 Walmart Gift Card! Claim within 24 hours at http://tinyurl.com/wm-claim"},
            "check": lambda res, data: res.status_code == 200 and data["assessment"]["category"] in ["High Concern", "Needs Review"] and len(data["indicators"]) >= 1,
            "expected": "High Concern / Needs Review with indicators detected"
        },
        {
            "id": "TC-03",
            "name": "Suspicious URL Structure (IP Hostname & Insecure HTTP)",
            "payload": {"message": "Review urgent security update at http://192.168.1.100/auth.apk immediately."},
            "check": lambda res, data: res.status_code == 200 and data["url_analysis"]["has_url"] is True and data["url_analysis"]["max_risk_level"] == "high",
            "expected": "Extracted URL flagged as high-risk (IP hostname + APK)"
        },
        {
            "id": "TC-04",
            "name": "Direct Credential & Password Phishing",
            "payload": {"message": "Your account is locked. Enter your password and PIN now to confirm your identity: http://verify-credentials.xyz"},
            "check": lambda res, data: res.status_code == 200 and any(i["id"] == "credential_harvesting" for i in data["indicators"]),
            "expected": "Credential harvesting indicator detected with matched evidence"
        },
        {
            "id": "TC-05",
            "name": "Banking Impersonation & Fake KYC Suspension",
            "payload": {"message": "Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN immediately at http://bit.ly/sbi-kyc"},
            "check": lambda res, data: res.status_code == 200 and data["assessment"]["category"] == "High Concern",
            "expected": "Classified as High Concern with brand impersonation & KYC indicators"
        },
        {
            "id": "TC-06",
            "name": "UPI Payment Trap (Social Engineering)",
            "payload": {"message": "You received Rs. 2,500 cashback! Enter UPI PIN to receive money in your account now."},
            "check": lambda res, data: res.status_code == 200 and any(i["id"] == "upi_payment_trap" for i in data["indicators"]) and any("UPI PIN" in r for r in data["assessment"]["recommendations"]),
            "expected": "UPI trap detected with specific UPI safety advice"
        },
        {
            "id": "TC-07",
            "name": "URL-Only Input",
            "payload": {"message": "http://bit.ly/claim-prize-now"},
            "check": lambda res, data: res.status_code == 200 and data["url_analysis"]["has_url"] is True and data["url_analysis"]["urls"][0]["is_shortener"] is True,
            "expected": "URL parsed and identified as shortener service"
        },
        {
            "id": "TC-08",
            "name": "Blank / Empty Input Validation",
            "payload": {"message": "   "},
            "check": lambda res, data: res.status_code == 400 and "error" in data,
            "expected": "HTTP 400 Bad Request with validation message"
        },
        {
            "id": "TC-09",
            "name": "Long Message Handling (> 5000 Chars)",
            "payload": {"message": "A" * 5050},
            "check": lambda res, data: res.status_code == 400 and "cannot exceed 5000" in data.get("error", ""),
            "expected": "HTTP 400 Bad Request safely rejecting oversized payload"
        },
        {
            "id": "TC-10",
            "name": "Malformed Request (Non-JSON / Invalid Type)",
            "payload": None,
            "check": lambda res, data: res.status_code == 400 and "error" in data,
            "expected": "HTTP 400 Bad Request for invalid request format"
        },
        {
            "id": "TC-11",
            "name": "Regional Social Engineering (Indian Electricity Scam)",
            "payload": {"message": "Dear consumer your electricity power will be disconnected tonight at 9.30 PM because previous month bill was not updated. Contact officer 9876543210"},
            "check": lambda res, data: res.status_code == 200 and any(i["id"] == "utility_disconnection" for i in data["indicators"]),
            "expected": "Utility disconnection lure detected with official helpline advice"
        },
        {
            "id": "TC-12",
            "name": "Dedicated Pre-Click URL Check Endpoint (/api/url-check)",
            "payload": "URL_ENDPOINT",
            "check": lambda res, data: res.status_code == 200 and data["action"] == "BLOCK_RECOMMENDED" and data["risk_level"] == "high",
            "expected": "URL evaluated and block recommended for shortened/suspicious link"
        }
    ]

    for tc in test_cases:
        total += 1
        start_time = time.time()

        if tc["payload"] == "URL_ENDPOINT":
            res = client.post("/api/url-check", json={"url": "http://bit.ly/sbi-verify-kyc"})
        elif tc["payload"] is None:
            res = client.post("/api/predict", data="NOT_JSON", content_type="text/plain")
        else:
            res = client.post("/api/predict", json=tc["payload"])

        latency_ms = (time.time() - start_time) * 1000

        try:
            data = res.get_json(silent=True) or {}
            is_pass = tc["check"](res, data)
        except Exception as e:
            is_pass = False
            data = {"exception": str(e)}

        if is_pass:
            passed += 1
            status_str = "[PASS]"
        else:
            status_str = "[FAIL]"

        print(f"{status_str} {tc['id']}: {tc['name']} ({latency_ms:.1f}ms)")
        print(f"       Expected: {tc['expected']}")
        if not is_pass:
            print(f"       Actual Status: {res.status_code}, Body: {data}")

    print("\n========================================================")
    print(f"TEST RESULTS: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("========================================================\n")
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
