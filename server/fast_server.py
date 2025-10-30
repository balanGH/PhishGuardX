"""
Optimized Comprehensive Phishing Detection System
- Parallelized slow checks with ThreadPoolExecutor
- Caching for WHOIS/SSL/IP lookups (functools.lru_cache)
- Optional "quick" mode (skip screenshots/CNN and some checks)
- Lazy Selenium initialization (only if enabled and not quick)
- GPU detection for PyTorch models (if available)
- Reduced DistilBERT token length and joined text input for speed
- Shorter network timeouts and safer exception handling

Usage:
    python phish_detector_fast.py
    -> Runs FastAPI on 0.0.0.0:8081

Endpoints:
    GET /detect?url=<url>&quick=true    -> quick mode (faster)
    GET /detect/html?url=<url>&quick=true
"""

import os
import re
import json
import time
import ssl
import socket
import ipaddress
import threading
from datetime import datetime
from urllib.parse import urlparse
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup

# PyTorch + Transformers
import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import transforms
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

# Optional image + OCR + selenium
from PIL import Image
import pytesseract

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn

# -----------------------------
# Configuration / Flags
# -----------------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"  # adjust if needed

# Toggle whether to use Selenium at all (set False to avoid webdriver overhead)
SELENIUM_ENABLED = False

# Default: quick mode off. FastAPI supports ?quick=true to enable.
DEFAULT_QUICK_MODE = False

# Shorter network timeouts to avoid long hanging calls
REQUESTS_TIMEOUT = 7
SOCKET_TIMEOUT = 7

# DistilBERT model dir
MODEL_DIR = "./distilbert_url_model_demo"

# Trusted domains & patterns (same as your original)
TRUSTED_DOMAINS = {
    "paypal.com", "www.paypal.com", "login.paypal.com",
    "google.com", "www.google.com", "accounts.google.com",
    "microsoft.com", "facebook.com", "github.com",
    "amazon.com", "apple.com", "twitter.com", "youtube.com", "linkedin.com"
}
SUSPICIOUS_PATTERNS = {
    "keywords": ["secure", "login", "verify", "account", "bank", "update", "security", "confirm"],
    "tlds": [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club", ".info", ".biz"],
    "brands": ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix", "instagram", "whatsapp"]
}

# -----------------------------
# Device / Model Loading (GPU aware)
# -----------------------------
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

# CNN model (same architecture, but loaded to device)
class EnhancedPhishingCNN(nn.Module):
    def __init__(self):
        super(EnhancedPhishingCNN, self).__init__()
        self.conv1 = nn.Conv2d(3, 32, 3, 1, 1)
        self.pool = nn.MaxPool2d(2,2)
        self.conv2 = nn.Conv2d(32, 64, 3, 1, 1)
        self.conv3 = nn.Conv2d(64, 128, 3, 1, 1)
        # For 128x128 input, after 3 pools -> 16x16
        self.fc1 = nn.Linear(128 * 16 * 16, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, 2)
        self.dropout = nn.Dropout(0.5)
        
    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = self.pool(F.relu(self.conv3(x)))
        x = x.view(-1, 128 * 16 * 16)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x

# Minimal transforms (do not set weird normalization channels)
cnn_transform = transforms.Compose([
    transforms.Resize((128, 128)),
    transforms.ToTensor(),
])

cnn_model = EnhancedPhishingCNN().to(device)
cnn_model.eval()

# -----------------------------
# DistilBERT tokenizer & model (loaded if available)
# -----------------------------
tokenizer = None
distilbert_model = None
PHISHING_THRESHOLD = 0.5

try:
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
    distilbert_model = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
    distilbert_model.eval()
    thresh_file = os.path.join(MODEL_DIR, "threshold.json")
    if os.path.exists(thresh_file):
        with open(thresh_file) as f:
            tdata = json.load(f)
            PHISHING_THRESHOLD = tdata.get("threshold", PHISHING_THRESHOLD)
    print(f"DistilBERT loaded (threshold={PHISHING_THRESHOLD})")
except Exception as e:
    print(f"DistilBERT not loaded: {e}")
    tokenizer = None
    distilbert_model = None

# -----------------------------
# Lazy Selenium helper (only if SELENIUM_ENABLED)
# -----------------------------
driver_lock = threading.Lock()
driver = None

def get_selenium_driver():
    global driver
    if not SELENIUM_ENABLED:
        return None
    with driver_lock:
        if driver is None:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                from selenium.webdriver.chrome.service import Service
                from webdriver_manager.chrome import ChromeDriverManager

                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--window-size=1920,1080")
                # reduce logging noise
                chrome_options.add_argument("--log-level=3")
                
                driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
            except Exception as e:
                print(f"Selenium init failed: {e}")
                driver = None
        return driver

def capture_screenshot(url, filename="screenshot.png", timeout=7):
    """
    Lazy selenium screenshot. If selenium not available or disabled, fallback to requests->save HTML snapshot.
    """
    print("   📸 Capturing screenshot (lazy)...")
    drv = get_selenium_driver()
    if drv is None:
        # fallback: try to fetch via requests and save a simple image placeholder or HTML snapshot
        try:
            resp = requests.get(url, timeout=REQUESTS_TIMEOUT, verify=False)
            html_path = filename.replace(".png", ".html")
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(resp.text[:200000])  # limit saving
            # create a small placeholder image so downstream code can open something
            img = Image.new("RGB", (800, 600), color=(255,255,255))
            img.save(filename)
            return filename
        except Exception as e:
            print(f"   ❌ Screenshot fallback error: {e}")
            # create placeholder
            img = Image.new("RGB", (800, 600), color=(255,255,255))
            img.save(filename)
            return filename

    try:
        drv.set_page_load_timeout(timeout)
        drv.get(url)
        # Wait for readyState (simple polling, faster than fixed sleep)
        max_wait = timeout
        poll = 0.2
        waited = 0.0
        ready = False
        while waited < max_wait:
            try:
                state = drv.execute_script("return document.readyState")
                if state == "complete":
                    ready = True
                    break
            except:
                pass
            time.sleep(poll)
            waited += poll
        drv.save_screenshot(filename)
        return filename
    except Exception as e:
        print(f"   ❌ Selenium screenshot error: {e}")
        # fallback: placeholder
        try:
            img = Image.new("RGB", (800, 600), color=(255,255,255))
            img.save(filename)
        except:
            pass
        return filename

# -----------------------------
# Utility / Heuristics (unchanged logic but faster)
# -----------------------------
def is_trusted_domain(url):
    domain = urlparse(url).netloc.lower()
    for trusted_domain in TRUSTED_DOMAINS:
        if domain == trusted_domain or domain.endswith('.' + trusted_domain):
            return True
    return False

def contains_brand_name(url):
    domain = urlparse(url).netloc.lower()
    for brand in SUSPICIOUS_PATTERNS["brands"]:
        if brand in domain:
            if not any(trusted in domain for trusted in [f"{brand}.com", f"www.{brand}.com", f"login.{brand}.com"]):
                return True, brand
    return False, None

def enhanced_heuristic_check(url):
    # no prints here to reduce overhead; return flags list
    flags = []
    domain = urlparse(url).netloc.lower()
    has_brand, brand_name = contains_brand_name(url)
    if has_brand:
        flags.append(f"Possible {brand_name} typosquatting/phishing")
    if len(domain) > 25:
        flags.append(f"Long domain name ({len(domain)} chars)")
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        flags.append(f"Multiple hyphens in domain ({hyphen_count})")
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        tld = domain_parts[-1]
        if ("." + tld) in SUSPICIOUS_PATTERNS["tlds"] or tld in SUSPICIOUS_PATTERNS["tlds"]:
            flags.append(f"Suspicious TLD: .{tld}")
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        flags.append("IP address in domain (suspicious)")
    if not url.startswith('https://'):
        flags.append("No HTTPS (insecure connection - HIGH RISK)")
    subdomain_count = domain.count('.')
    if subdomain_count >= 3:
        flags.append(f"Too many subdomains ({subdomain_count})")
    suspicious_keywords = ["secure", "login", "verify", "account", "bank", "update", "confirm"]
    for kw in suspicious_keywords:
        if kw in domain:
            flags.append(f"Suspicious keyword '{kw}' in domain")
    if re.search(r'\d', domain):
        flags.append("Numbers in domain (suspicious)")
    return flags

# -----------------------------
# Cached network checks to avoid repeated lookup cost
# -----------------------------
@lru_cache(maxsize=256)
def _whois_lookup(domain):
    # Avoid importing whois until needed to reduce startup overhead
    try:
        import whois
        return whois.whois(domain)
    except Exception as e:
        # Return None on failure
        return None

@lru_cache(maxsize=512)
def check_domain_registration_cached(domain):
    """
    domain: netloc or domain string
    returns: (flags_list, domain_age_days)
    """
    flags = []
    domain_info = _whois_lookup(domain)
    domain_age = 365
    try:
        if domain_info and getattr(domain_info, "creation_date", None):
            creation_date = domain_info.creation_date
            # handle lists
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(creation_date, str):
                # try parsing string formats robustly
                try:
                    creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                except:
                    try:
                        creation_date = datetime.fromisoformat(creation_date)
                    except:
                        creation_date = None
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 7:
                    flags.append(f"Very new domain ({domain_age} days old - HIGH RISK)")
                elif domain_age < 30:
                    flags.append(f"New domain ({domain_age} days old)")
                elif domain_age < 365:
                    flags.append(f"Relatively new domain ({domain_age} days old)")
        else:
            flags.append("Domain WHOIS information hidden or unavailable")
    except Exception:
        flags.append("Domain WHOIS parse error")
    return flags, domain_age

@lru_cache(maxsize=512)
def check_ssl_certificate_cached(domain):
    flags = []
    if not domain:
        return ["No domain provided"], []
    if not domain.startswith("http://") and not domain.startswith("https://"):
        host = domain
    else:
        host = urlparse(domain).netloc

    # if scheme not https, immediate flag
    # For more precise, accept both
    if not host:
        return ["Invalid domain for SSL"], flags
    try:
        # attempt socket connect
        ctx = ssl.create_default_context()
        # don't verify to just fetch cert quickly
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # 'notAfter' example: 'May 12 23:59:59 2025 GMT'
                    not_after = cert.get('notAfter')
                    if not_after:
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        except Exception:
                            try:
                                expiry_date = datetime.strptime(not_after, '%Y-%m-%d %H:%M:%S')
                            except:
                                expiry_date = None
                        if expiry_date:
                            days_until_expiry = (expiry_date - datetime.now()).days
                            if days_until_expiry < 7:
                                flags.append(f"SSL certificate expires soon ({days_until_expiry} days - HIGH RISK)")
                            elif days_until_expiry < 30:
                                flags.append(f"SSL certificate expires in {days_until_expiry} days")
                else:
                    flags.append("No valid SSL certificate found")
    except Exception as e:
        flags.append(f"SSL certificate error: {str(e)}")
    return flags

@lru_cache(maxsize=1024)
def check_ip_reputation_cached(domain):
    flags = []
    ip = "Unknown"
    try:
        # domain might be netloc or full url
        host = domain
        if "/" in host:
            host = urlparse(host).netloc
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            flags.append("Private IP address range (suspicious)")
        suspicious_ranges = [
            "185.161.248", "194.87.145", "45.142.215", "23.227.38",
            "104.168.162", "192.241.230", "198.54.132", "203.176.135"
        ]
        for prefix in suspicious_ranges:
            if ip.startswith(prefix):
                flags.append(f"IP in suspicious range: {prefix}")
    except Exception as e:
        flags.append("Could not resolve IP address")
    return flags, ip

# -----------------------------
# Fetch page text (faster)
# -----------------------------
def fetch_page_text(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        r = requests.get(url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup(["script", "style"]):
            script.decompose()
        important_texts = []
        for tag in soup.find_all(["title", "h1", "h2", "h3", "a", "button", "input"]):
            text = ""
            if tag.name == "input":
                text = tag.get('value', '') or tag.get('placeholder', '')
            else:
                text = tag.get_text(strip=True)
            if text and len(text) > 2:
                important_texts.append(text)
        return important_texts
    except Exception:
        # fallback suspicious tokens to ensure model has input
        return ["login", "password", "verify", "account"]

# -----------------------------
# DistilBERT inference (faster: combine texts, shorter max_length)
# -----------------------------
def predict_text_distilbert(texts, url):
    if not tokenizer or not distilbert_model:
        # fallback heuristic
        has_brand, _ = contains_brand_name(url)
        return (1, 0.8) if has_brand else (0, 0.3)
    try:
        if not texts:
            texts = [url]
        # join for one pass (faster)
        joined = " ".join(texts)
        # lower token length to speed up
        max_len = 256
        inputs = tokenizer(joined, return_tensors="pt", truncation=True, padding=True, max_length=max_len)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = distilbert_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            phishing_prob = float(probs[0][1].cpu().numpy())
            result = 1 if phishing_prob >= PHISHING_THRESHOLD else 0
        return result, phishing_prob
    except Exception:
        has_brand, _ = contains_brand_name(url)
        return (1, 0.7) if has_brand else (0, 0.4)

# -----------------------------
# CNN Visual analysis (uses device, quick fallback)
# -----------------------------
def preprocess_image_for_cnn(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        tensor = cnn_transform(img).unsqueeze(0).to(device)
        return tensor, img.size
    except Exception:
        # return random tensor to avoid crashing
        return torch.randn(1, 3, 128, 128).to(device), (128, 128)

def analyze_visual_cnn(image_path, url):
    try:
        image_tensor, (width, height) = preprocess_image_for_cnn(image_path)
        with torch.no_grad():
            outputs = cnn_model(image_tensor)
            probabilities = F.softmax(outputs, dim=1)
            phishing_prob = probabilities[0][1].item()
        visual_flags = []
        if width < 800 or height < 600:
            visual_flags.append("Suspicious small page dimensions")
        if phishing_prob > 0.6:
            visual_flags.append("Visual pattern matches phishing pages")
        return phishing_prob, visual_flags
    except Exception:
        return 0.6, ["Visual analysis failed - assuming suspicious"]

# -----------------------------
# Scoring (same as original logic)
# -----------------------------
def comprehensive_risk_scoring(distilbert_prob, cnn_prob, heuristic_flags, domain_age, ssl_flags, ip_flags, url):
    distilbert_weight = 0.30
    cnn_weight = 0.20
    heuristic_weight = 0.25
    ssl_weight = 0.12
    ip_weight = 0.08
    domain_age_weight = 0.05

    distilbert_score = distilbert_prob * distilbert_weight
    cnn_score = cnn_prob * cnn_weight
    heuristic_score = min(len(heuristic_flags) * 0.12, heuristic_weight)
    ssl_penalty = 0
    for flag in ssl_flags:
        if "HIGH RISK" in flag:
            ssl_penalty += 0.08
        else:
            ssl_penalty += 0.04
    ssl_score = min(ssl_penalty, ssl_weight)
    ip_score = min(len(ip_flags) * 0.06, ip_weight)

    domain_age_penalty = 0.0
    if domain_age < 365:
        if domain_age < 7:
            domain_age_penalty = domain_age_weight * 1.5
        else:
            domain_age_penalty = (365 - domain_age) / 365 * domain_age_weight

    brand_penalty = 0.0
    if contains_brand_name(url)[0]:
        brand_penalty = 0.15

    combined_score = (distilbert_score + cnn_score + heuristic_score +
                     ssl_score + ip_score + domain_age_penalty + brand_penalty)
    combined_score = min(combined_score, 1.0)
    return combined_score

# -----------------------------
# Result HTML builder (same)
# -----------------------------
def create_comprehensive_result(url, status, score, flags, distilbert_prob, cnn_prob, reason, steps_html):
    if status == "🚨 PHISHING ALERT":
        color_style = "background:#ffcccc; color:#cc0000; border-left:5px solid #cc0000;"
        icon = "🚨"
    elif "HIGHLY SUSPICIOUS" in status:
        color_style = "background:#ff9900; color:#ffffff; border-left:5px solid #cc6600;"
        icon = "⚠️"
    elif "SUSPICIOUS" in status:
        color_style = "background:#fff0cc; color:#cc6600; border-left:5px solid #cc6600;"
        icon = "⚠️"
    else:
        color_style = "background:#ccffcc; color:#006600; border-left:5px solid #006600;"
        icon = "✅"
    flags_html = ""
    for flag in flags:
        if "HIGH RISK" in flag:
            flags_html += f"<li>🔴 <strong>{flag}</strong></li>"
        else:
            flags_html += f"<li>⚠️ {flag}</li>"
    if not flags_html:
        flags_html = "<li>✅ No suspicious indicators detected</li>"
    risk_level = ""
    if score >= 0.6:
        risk_level = "🔴 HIGH RISK"
    elif score >= 0.4:
        risk_level = "🟠 MEDIUM-HIGH RISK"
    elif score >= 0.25:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    return f"""
    <div style='padding:20px; background:#f9f9f9; border-radius:10px;'>
        <h2>🔗 Comprehensive Phishing Analysis</h2>
        <p><strong>URL:</strong> <code>{url}</code></p>
        <div style='margin:20px 0; padding:15px; {color_style} border-radius:5px;'>
            <h3>{icon} {status}</h3>
            <p><strong>Risk Score:</strong> {score:.2f}/1.0 - {risk_level}</p>
            <p><strong>Reason:</strong> {reason}</p>
        </div>
        <div style='margin:20px 0; padding:15px; background:#f0f8ff; border-radius:5px;'>
            <h4>📋 Analysis Steps</h4>
            {steps_html}
        </div>
        <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;'>
            <div style='padding:15px; background:#e6f3ff; border-radius:5px;'>
                <h4>🤖 AI Model Scores</h4>
                <p><strong>DistilBERT Text Analysis:</strong> {distilbert_prob:.4f}</p>
                <p><strong>CNN Visual Analysis:</strong> {cnn_prob:.4f}</p>
            </div>
            <div style='padding:15px; background:#f0f0f0; border-radius:5px;'>
                <h4>🔍 Detection Indicators</h4>
                <ul style='margin:0; padding-left:20px;'>
                    {flags_html}
                </ul>
            </div>
        </div>
    </div>
    """

# -----------------------------
# Main comprehensive analyzer (parallelized + quick mode)
# -----------------------------
def comprehensive_analyze_url(url, quick=False):
    start_time = time.time()
    steps_html = ""

    def add_step(step_number, step_name, status, details=""):
        nonlocal steps_html
        icon = "✅" if status == "completed" else "⏳" if status == "processing" else "❌"
        color = "#d4edda" if status == "completed" else "#fff3cd" if status == "processing" else "#f8d7da"
        step_html = f"""
        <div style='padding:10px; margin:5px 0; background:{color}; border-radius:5px; border-left:4px solid #007bff;'>
            <strong>Step {step_number}:</strong> {step_name} {icon}<br>
            <small style='color:#666;'>{details}</small>
        </div>
        """
        steps_html += step_html

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Step 1: Trusted domain check
    add_step(1, "Trusted Domain Check", "processing", "Checking if domain is in trusted list...")
    if is_trusted_domain(url):
        add_step(1, "Trusted Domain Check", "completed", "Domain is trusted")
        return create_comprehensive_result(url, "✅ SAFE URL", 0.1, [], 0.1, 0.1, "Trusted domain", steps_html)

    add_step(1, "Trusted Domain Check", "completed", "Domain not in trusted list - proceeding")

    # Step 2: Heuristics
    add_step(2, "Heuristic Analysis", "processing", "Analyzing URL patterns and structure...")
    heuristic_flags = enhanced_heuristic_check(url)
    add_step(2, "Heuristic Analysis", "completed", f"Found {len(heuristic_flags)} suspicious indicators")

    # Steps 3-5: parallel WHOIS/SSL/IP (these are independent and slow -> parallelize)
    add_step(3, "Domain Registration Check", "processing", "WHOIS lookup (cached)")
    add_step(4, "SSL Certificate Validation", "processing", "SSL check (cached)")
    add_step(5, "IP Reputation Check", "processing", "IP resolution & checks (cached)")

    parsed_netloc = urlparse(url).netloc

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_domain = executor.submit(check_domain_registration_cached, parsed_netloc)
        f_ssl = executor.submit(check_ssl_certificate_cached, parsed_netloc)
        f_ip = executor.submit(check_ip_reputation_cached, parsed_netloc)
        domain_flags, domain_age = f_domain.result()
        ssl_flags = f_ssl.result()
        ip_flags, ip_address = f_ip.result()

    heuristic_flags.extend(domain_flags)
    add_step(3, "Domain Registration Check", "completed", f"Domain age: {domain_age} days, flags: {len(domain_flags)}")
    add_step(4, "SSL Certificate Validation", "completed", f"Found {len(ssl_flags)} SSL issues")
    add_step(5, "IP Reputation Check", "completed", f"IP: {ip_address}, flags: {len(ip_flags)}")

    # Step 6: DistilBERT (text) analysis
    add_step(6, "AI Text Analysis (DistilBERT)", "processing", "Analyzing page content with NLP...")
    texts = fetch_page_text(url)
    distilbert_result, distilbert_prob = predict_text_distilbert(texts, url)
    add_step(6, "AI Text Analysis (DistilBERT)", "completed", f"Phishing probability: {distilbert_prob:.4f}")

    # Step 7: Visual analysis - optional in quick mode
    add_step(7, "Visual Analysis (CNN)", "processing", "Capturing screenshot and analyzing layout...")
    if quick:
        cnn_prob, visual_flags = 0.3, []
        add_step(7, "Visual Analysis (CNN)", "completed", "Quick mode: skipped screenshot/CNN")
    else:
        screenshot_file = capture_screenshot(url, "screenshot.png")
        cnn_prob, visual_flags = analyze_visual_cnn(screenshot_file, url)
        heuristic_flags.extend(visual_flags)
        add_step(7, "Visual Analysis (CNN)", "completed", f"Visual phishing probability: {cnn_prob:.4f}")

    # Step 8: Scoring
    add_step(8, "Risk Scoring", "processing", "Calculating comprehensive risk score...")
    combined_score = comprehensive_risk_scoring(distilbert_prob, cnn_prob, heuristic_flags, domain_age, ssl_flags, ip_flags, url)
    add_step(8, "Risk Scoring", "completed", f"Final risk score: {combined_score:.4f}")

    # Step 9: Final classification
    add_step(9, "Final Classification", "processing", "Determining final verdict...")
    if combined_score >= 0.6:
        final_status = "🚨 PHISHING ALERT"
        reason = "High probability of phishing based on multiple factors"
    elif combined_score >= 0.4:
        final_status = "⚠️ HIGHLY SUSPICIOUS"
        reason = "Multiple suspicious indicators detected"
    elif combined_score >= 0.25:
        final_status = "⚠️ SUSPICIOUS"
        reason = "Some suspicious indicators detected"
    else:
        final_status = "✅ LIKELY SAFE"
        reason = "No significant suspicious indicators detected"
    add_step(9, "Final Classification", "completed", f"Verdict: {final_status}")

    total_time = time.time() - start_time
    print(f"[INFO] Analysis for {url} took {total_time:.2f}s (quick={quick})")

    all_flags = heuristic_flags + ssl_flags + ip_flags
    return create_comprehensive_result(url, final_status, combined_score, all_flags, distilbert_prob, cnn_prob, reason, steps_html)

# -----------------------------
# FastAPI endpoints (supports quick mode)
# -----------------------------
app = FastAPI(title="Optimized Phishing Detection API")

@app.get("/detect")
def detect_phishing(url: str = Query(...), quick: bool = Query(DEFAULT_QUICK_MODE)):
    try:
        print(f"API Request: {url} (quick={quick})")
        result_html = comprehensive_analyze_url(url, quick=quick)
        # extract some info
        score_match = re.search(r"Risk Score:</strong> ([0-9.]+)", result_html)
        status_match = re.search(r"<h3>(.*?)</h3>", result_html)
        response_data = {
            "url": url,
            "status": "success",
            "analysis": {
                "risk_score": float(score_match.group(1)) if score_match else 0.0,
                "verdict": status_match.group(1) if status_match else "Unknown",
                "timestamp": datetime.now().isoformat()
            },
            "html_result": result_html
        }
        return JSONResponse(content=response_data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e), "timestamp": datetime.now().isoformat()})

@app.get("/detect/html", response_class=HTMLResponse)
def detect_phishing_html(url: str = Query(...), quick: bool = Query(DEFAULT_QUICK_MODE)):
    try:
        return comprehensive_analyze_url(url, quick=quick)
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"

@app.get("/")
def root():
    return {"message": "Optimized Phishing Detection API", "version": "1.0", "quick_mode": DEFAULT_QUICK_MODE}

# -----------------------------
# Run server
# -----------------------------
if __name__ == "__main__":
    print("Starting Optimized Phishing Detection API on port 8081")
    print("Set SELENIUM_ENABLED=True at top if you want screenshot/CNN mode (slower).")
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
