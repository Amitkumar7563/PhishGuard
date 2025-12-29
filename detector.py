import os
import requests
from urllib.parse import urlparse
import socket
import google.generativeai as genai

#  API KEYS
SAFE_BROWSING_KEY = "AIzaSyCUCziB0qOmDw6slOeRss7jmWNf7W0Caow"
GEMINI_API_KEY = "AIzaSyCb42_ckc2adNNJf9hnDlIst2dYKAIPrX4" 

# Gemini setup
genai.configure(api_key=GEMINI_API_KEY)

# ----------------- HELPER FUNCTIONS -----------------

def is_valid_url(url):
    """Check if the URL has a valid scheme and network location."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except:
        return False

def domain_exists(url):
    """Check if the domain actually exists via DNS lookup."""
    try:
        domain = urlparse(url).netloc
        socket.gethostbyname(domain)
        return True
    except:
        return False

def is_https(url):
    """Check if the protocol is HTTPS."""
    return url.startswith("https://")

def check_tld(url):
    """Check if the TLD is in our trusted list."""
    trusted_tlds = [".com", ".org", ".net", ".in", ".edu", ".gov"]
    return any(url.lower().endswith(tld) for tld in trusted_tlds)

# ----------------- GOOGLE SAFE BROWSING -----------------

def check_phishing_google(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "phishguard-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload)
        return response.json()
    except Exception as e:
        print(f"Google API Error: {e}")
        return {}

# ----------------- MAIN ANALYSIS FUNCTIONS -----------------

def check_url(url):
    # Basic validation
    if not is_valid_url(url):
        return {"phishing": True, "https": False, "domain": False, "google_safe": False}

    # DNS validation
    if not domain_exists(url):
        return {"phishing": True, "https": is_https(url), "domain": False, "google_safe": False}

    # Google API check
    google_res = check_phishing_google(url)
    is_malicious = "matches" in google_res

    return {
        "phishing": is_malicious,
        "https": is_https(url),
        "domain": True,
        "google_safe": not is_malicious
    }

def gemini_analysis(url, checks, risk):
    try:
        # Latest model name 'gemini-1.5-flash'
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = f"""
        You are a cybersecurity expert.
        Analyze this website:
        URL: {url}
        Technical Checks: {checks}
        Calculated Risk Score: {risk}/100

        Please provide:
        1. Verdict: (Phishing/Suspicious/Safe)
        2. Reasoning: Why did it get this score?
        3. Safety Tip: A short one-line advice for the user.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini Analysis Error: {e}")
        return "AI Analysis is currently unavailable. Please rely on technical checks."