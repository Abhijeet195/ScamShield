"""
ScamShield URL Risk Analyzer
Analyzes embedded URLs and domain structures for suspicious indicators.
Designed to run safely without making external network requests to untrusted URLs (SSRF-safe).
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Any

# Common URL shortening services frequently abused in smishing
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "goo.gl", "lnkd.in",
    "rebrand.ly", "bl.ink", "t.ly", "qr.ae", "s.id", "v.gd"
}

# Suspicious or high-abuse Top Level Domains
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
    ".work", ".loan", ".click", ".download", ".racing", ".accountant",
    ".live", ".shop", ".site", ".online", ".vip", ".cc", ".to", ".info",
    ".monster", ".rest", ".cam", ".icu"
}

# Keywords frequently combined with brand names or security lures in phishing domains
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "update",
    "kyc", "pan", "aadhaar", "banking", "wallet", "support", "service",
    "alert", "account", "suspended", "confirm", "claim", "reward", "prize",
    "gift", "cash", "bonus", "winner", "portal", "helpdesk", "otp", "yono",
    "sbicard", "hdfcbank", "icicibank", "paytm", "phonepe", "gpay"
]

# Regex pattern for extracting URLs (both with protocol and common naked domains)
URL_REGEX = re.compile(
    r'(?:(?:https?|ftp)://|www\.)[^\s/$.?#].[^\s]*'
    r'|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|in|co|io|xyz|top|site|online|app|me|info|gov|edu|mil|biz|tv|cc)/[^\s]*'
    r'|(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)/[a-zA-Z0-9_-]+',
    re.IGNORECASE
)

# Pattern to test if hostname is an IP address
IPV4_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from a message string."""
    if not text or not isinstance(text, str):
        return []
    
    matches = URL_REGEX.findall(text)
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in matches:
        # Strip trailing punctuation that might have been caught from sentences
        cleaned_url = url.rstrip('.,;:!?)>"\'')
        if cleaned_url and cleaned_url not in seen:
            seen.add(cleaned_url)
            unique_urls.append(cleaned_url)
    return unique_urls


def is_ip_hostname(hostname: str) -> bool:
    """Check if the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_single_url(raw_url: str) -> Dict[str, Any]:
    """
    Perform structural and heuristic risk inspection on a single URL.
    Does NOT fetch or query the URL over the network.
    """
    # Ensure scheme exists for parsing
    has_scheme = raw_url.startswith(("http://", "https://", "ftp://"))
    url_to_parse = raw_url if has_scheme else f"http://{raw_url}"
    
    parsed = urlparse(url_to_parse)
    netloc = parsed.netloc.lower()
    
    # Strip port number if present
    hostname = netloc.split(':')[0] if ':' in netloc else netloc
    path = parsed.path.lower()
    full_str = f"{hostname}{path}"
    
    flags: List[str] = []
    risk_level = "low"
    
    # Check 1: Scheme check
    uses_https = parsed.scheme.lower() == "https"
    if not uses_https and has_scheme:
        flags.append("Unencrypted connection (HTTP instead of HTTPS)")
    
    # Check 2: IP address hostname
    if is_ip_hostname(hostname):
        flags.append("Hostname is a direct numeric IP address instead of a domain")
        risk_level = "high"
    
    # Check 3: Known URL shortening service
    is_shortener = hostname in KNOWN_SHORTENERS or any(hostname.endswith("." + s) for s in KNOWN_SHORTENERS)
    if is_shortener:
        flags.append("Uses a URL shortening service that conceals destination")
        if risk_level != "high":
            risk_level = "medium"
            
    # Check 4: Suspicious TLD
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            flags.append(f"Uses high-risk top-level domain ({tld})")
            risk_level = "high"
            break
            
    # Check 5: Punycode or suspicious internationalized domain
    if "xn--" in hostname:
        flags.append("Contains Punycode (possible IDN homograph impersonation attack)")
        risk_level = "high"
        
    # Check 6: Suspicious subdomains or excess dot count (for domain names only)
    if not is_ip_hostname(hostname):
        subdomain_parts = [p for p in hostname.split('.') if p]
        if len(subdomain_parts) > 3:
            flags.append("Excessive subdomain depth (potential domain obfuscation)")
            if risk_level == "low":
                risk_level = "medium"
            
    # Check 7: Suspicious keywords in domain or path
    found_keywords = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in full_str]
    if found_keywords:
        # Check if the keyword is suspicious in this context
        kw_display = ", ".join(found_keywords[:3])
        flags.append(f"Contains security/sensitive keywords: {kw_display}")
        if is_shortener or matched_tld or not uses_https:
            risk_level = "high"
        elif risk_level == "low":
            risk_level = "medium"
            
    # Check 8: @ symbol in URL (HTTP basic auth deception)
    if "@" in parsed.netloc:
        flags.append("Contains '@' symbol in authority (credential phishing tactic)")
        risk_level = "high"
        
    # Check 9: File extension indicator (APK, EXE)
    if any(path.endswith(ext) for ext in [".apk", ".exe", ".scr", ".bat", ".vbs"]):
        flags.append("Direct link to executable / Android package file (.apk/.exe)")
        risk_level = "high"
        
    return {
        "raw_url": raw_url,
        "hostname": hostname or "(unresolved)",
        "protocol": parsed.scheme if has_scheme else "none_specified",
        "uses_https": uses_https,
        "is_shortener": is_shortener,
        "is_ip_address": is_ip_hostname(hostname),
        "flags": flags,
        "risk_level": risk_level
    }


def analyze_urls_in_text(text: str) -> Dict[str, Any]:
    """
    Extract and analyze all URLs present in a given message.
    """
    extracted = extract_urls(text)
    
    if not extracted:
        return {
            "has_url": False,
            "url_count": 0,
            "urls": [],
            "max_risk_level": "none",
            "summary": "No external URLs or links detected."
        }
        
    analyzed_urls = [analyze_single_url(u) for u in extracted]
    
    # Determine maximum risk level across all extracted URLs
    has_high = any(u["risk_level"] == "high" for u in analyzed_urls)
    has_med = any(u["risk_level"] == "medium" for u in analyzed_urls)
    
    if has_high:
        max_risk = "high"
        summary = "High-risk URL patterns detected (shortener, suspicious TLD, or IP hostname)."
    elif has_med:
        max_risk = "medium"
        summary = "Moderately suspicious link indicators detected (review carefully)."
    else:
        max_risk = "low"
        summary = "Standard URL structure detected. Exercise standard caution before clicking."
        
    return {
        "has_url": True,
        "url_count": len(analyzed_urls),
        "urls": analyzed_urls,
        "max_risk_level": max_risk,
        "summary": summary
    }
