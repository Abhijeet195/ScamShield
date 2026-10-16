# ScamShield Browser Extension (Pre-Click Link Protection)

The **ScamShield Chrome & Edge Extension** implements proactive **Pre-Click Link Protection** (addressing Problem Statement Priority 6).

Instead of waiting for users to paste a message after being exposed, the extension intercepts clicks on links inside webmail, web SMS portals, and chat applications before navigation occurs.

---

## ⚡ How It Works

1. **Pre-Click Heuristic & API Inspection:** When a link is clicked, the content script intercepts the navigation event and inspects the URL's structure (shorteners, numeric IP hostnames, suspicious TLDs, punycode, unencrypted HTTP).
2. **Pre-Click Warning Shield Modal:** If threat signals are detected, the extension blocks immediate page load and displays an on-screen warning card with identified risks, allowing the user to safely abort.
3. **Popup Quick Scanner:** Allows direct link analysis and connects to the local ScamShield API (`http://127.0.0.1:5000/api/url-check`).

---

## 🛠️ Installation in 30 Seconds

1. Open Google Chrome, Brave, or Microsoft Edge.
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select the `C:\ScamShield\extension` folder.
6. The ScamShield icon will appear in your browser toolbar!

---

## 🧪 Testing the Extension

1. Ensure the Flask backend is running (`python app.py`).
2. Click the ScamShield toolbar icon to test the quick URL inspector with test links:
   - `http://bit.ly/sbi-yono-kyc` (Shortened bank lure)
   - `http://192.168.1.50/safety.apk` (IP hostname with APK)
   - `https://google.com` (Standard link)
3. Open any webpage containing shortened or suspicious links (or test on the ScamShield React demo page) to see the in-page Pre-Click Intervention Modal in action!
