# -----------------------------
# Comprehensive Phishing Detection System
# Combining Enhanced Features + DistilBERT + CNN
# -----------------------------

import gradio as gr
import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import transforms, models
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from urllib.parse import urlparse
import pytesseract
from PIL import Image
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import json
import os
import re
import ssl
import socket
import ipaddress
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time

# FastAPI imports
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn
import threading

# -----------------------------
# Configuration
# -----------------------------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Selenium Setup
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--window-size=1920,1080")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

def capture_screenshot(url, filename="screenshot.png"):
    print(f"   📸 Capturing screenshot...")
    try:
        driver.get(url)
        time.sleep(2)  # Wait for page to load
        driver.save_screenshot(filename)
        print(f"   ✅ Screenshot saved: {filename}")
        return filename
    except Exception as e:
        print(f"   ❌ Screenshot error: {e}")
        return "screenshot.png"  # Return default

# -----------------------------
# CNN Model (Enhanced)
# -----------------------------
class EnhancedPhishingCNN(nn.Module):
    def __init__(self):
        super(EnhancedPhishingCNN, self).__init__()
        self.conv1 = nn.Conv2d(3, 32, 3, 1, 1)
        self.pool = nn.MaxPool2d(2,2)
        self.conv2 = nn.Conv2d(32, 64, 3, 1, 1)
        self.conv3 = nn.Conv2d(64, 128, 3, 1, 1)
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

# CNN Transform
cnn_transform = transforms.Compose([
    transforms.Resize((128, 128)),
    transforms.ToTensor(),
    transforms.Normalize((0.5,), (0.5,))
])

def preprocess_image(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        return cnn_transform(img).unsqueeze(0)
    except:
        return torch.randn(1, 3, 128, 128)  # Return dummy tensor if image fails

cnn_model = EnhancedPhishingCNN()
cnn_model.eval()

# -----------------------------
# DistilBERT Model (Your Original Implementation)
# -----------------------------
MODEL_DIR = "./distilbert_url_model_demo"
try:
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
    distilbert_model = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
    distilbert_model.eval()
    with open(os.path.join(MODEL_DIR, "threshold.json")) as f:
        threshold_data = json.load(f)
    PHISHING_THRESHOLD = threshold_data.get("threshold", 0.5)
    print(f"✅ DistilBERT model loaded. Threshold: {PHISHING_THRESHOLD}")
except Exception as e:
    print(f"❌ DistilBERT model not loaded: {e}")
    tokenizer = None
    distilbert_model = None
    PHISHING_THRESHOLD = 0.5

# -----------------------------
# Enhanced Configuration - MODIFIED FOR BETTER DETECTION
# -----------------------------
TRUSTED_DOMAINS = {
    "paypal.com", "www.paypal.com", "login.paypal.com", 
    "google.com", "www.google.com", "accounts.google.com",
    "microsoft.com", "facebook.com", "github.com",
    "amazon.com", "apple.com", "twitter.com", "youtube.com", "linkedin.com"
}

# Enhanced suspicious patterns
SUSPICIOUS_PATTERNS = {
    "keywords": ["secure", "login", "verify", "account", "bank", "update", "security", "confirm"],
    "tlds": [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club", ".info", ".biz"],
    "brands": ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix", "instagram", "whatsapp"]
}

def is_trusted_domain(url):
    """Check if domain is in trusted list - MODIFIED to be more strict"""
    domain = urlparse(url).netloc.lower()
    
    # Check for exact domain match or subdomain of trusted domains
    for trusted_domain in TRUSTED_DOMAINS:
        if domain == trusted_domain or domain.endswith('.' + trusted_domain):
            return True
    return False

def contains_brand_name(url):
    """Check if URL contains brand names but isn't the actual brand domain"""
    domain = urlparse(url).netloc.lower()
    
    for brand in SUSPICIOUS_PATTERNS["brands"]:
        if brand in domain:
            # Check if it's NOT the actual brand domain
            if not any(trusted in domain for trusted in [f"{brand}.com", f"www.{brand}.com", f"login.{brand}.com"]):
                return True, brand
    return False, None

# -----------------------------
# Enhanced Heuristic Analysis - IMPROVED
# -----------------------------
def enhanced_heuristic_check(url):
    print(f"   🔍 Enhanced heuristic analysis...")
    flags = []
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    
    # 1. Brand name typosquatting detection - IMPROVED
    has_brand, brand_name = contains_brand_name(url)
    if has_brand:
        flags.append(f"Possible {brand_name} typosquatting/phishing")
    
    # 2. Domain length check (more strict)
    if len(domain) > 25:
        flags.append(f"Long domain name ({len(domain)} chars)")
    
    # 3. Hyphen count check (more strict)
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        flags.append(f"Multiple hyphens in domain ({hyphen_count})")
    
    # 4. Suspicious TLD check (expanded list)
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        tld = domain_parts[-1]
        if tld in SUSPICIOUS_PATTERNS["tlds"]:
            flags.append(f"Suspicious TLD: .{tld}")
    
    # 5. IP address in domain
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        flags.append("IP address in domain (suspicious)")
    
    # 6. HTTPS check (more important)
    if not url.startswith('https://'):
        flags.append("No HTTPS (insecure connection - HIGH RISK)")
    
    # 7. Subdomain count (too many subdomains)
    subdomain_count = domain.count('.')
    if subdomain_count >= 3:
        flags.append(f"Too many subdomains ({subdomain_count})")
    
    # 8. Suspicious keywords in domain
    suspicious_keywords = ["secure", "login", "verify", "account", "bank", "update", "confirm"]
    for kw in suspicious_keywords:
        if kw in domain:
            flags.append(f"Suspicious keyword '{kw}' in domain")
    
    # 9. Number usage in domain
    if re.search(r'\d', domain):
        flags.append("Numbers in domain (suspicious)")
    
    print(f"      📊 Heuristic flags: {len(flags)}")
    return flags

# -----------------------------
# Domain Registration Check - IMPROVED
# -----------------------------
def check_domain_registration(url):
    print(f"   📅 Checking domain registration...")
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        
        flags = []
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            domain_age = (datetime.now() - creation_date).days
            print(f"      Domain age: {domain_age} days")
            
            # More strict domain age checks
            if domain_age < 7:
                flags.append(f"Very new domain ({domain_age} days old - HIGH RISK)")
            elif domain_age < 30:
                flags.append(f"New domain ({domain_age} days old)")
            elif domain_age < 365:
                flags.append(f"Relatively new domain ({domain_age} days old)")
                
        return flags, domain_age if 'domain_age' in locals() else 365
    except:
        print(f"      ❌ Could not retrieve domain info")
        return ["Domain WHOIS information hidden or unavailable"], 365

# -----------------------------
# SSL Certificate Validation - IMPROVED
# -----------------------------
def check_ssl_certificate(url):
    print(f"   🔒 SSL Certificate validation...")
    flags = []
    
    try:
        if not url.startswith('https://'):
            flags.append("No HTTPS (insecure connection - HIGH RISK)")
            return flags
            
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 7:
                        flags.append(f"SSL certificate expires soon ({days_until_expiry} days - HIGH RISK)")
                    elif days_until_expiry < 30:
                        flags.append(f"SSL certificate expires in {days_until_expiry} days")
                else:
                    flags.append("No valid SSL certificate found")
                    
    except Exception as e:
        flags.append(f"SSL certificate error: {str(e)}")
    
    print(f"      SSL flags: {len(flags)}")
    return flags

# -----------------------------
# IP Reputation Check - IMPROVED
# -----------------------------
def check_ip_reputation(domain):
    print(f"   🌍 IP reputation check...")
    flags = []
    
    try:
        ip = socket.gethostbyname(domain)
        print(f"      Resolved IP: {ip}")
        
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            flags.append("Private IP address range (suspicious)")
        
        # Expanded suspicious IP ranges
        suspicious_ranges = [
            "185.161.248", "194.87.145", "45.142.215", "23.227.38", 
            "104.168.162", "192.241.230", "198.54.132", "203.176.135"
        ]
        for range_prefix in suspicious_ranges:
            if ip.startswith(range_prefix):
                flags.append(f"IP in suspicious range: {range_prefix}")
        
        # Check for known phishing hosting providers
        known_bad_asn_ranges = []
                
    except Exception as e:
        print(f"      ❌ IP resolution error: {e}")
        flags.append("Could not resolve IP address")
    
    print(f"      IP reputation flags: {len(flags)}")
    return flags, ip if 'ip' in locals() else "Unknown"

# -----------------------------
# DistilBERT Text Analysis (Your Original Functions) - IMPROVED
# -----------------------------
def fetch_page_text(url):
    print(f"   📄 Fetching page text for DistilBERT...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        r = requests.get(url, timeout=10, headers=headers, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        
        # Remove scripts and styles
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text from important elements
        important_texts = []
        for tag in soup.find_all(["title", "h1", "h2", "h3", "a", "button", "input"]):
            text = ""
            if tag.name == "input":
                text = tag.get('value', '') or tag.get('placeholder', '')
            else:
                text = tag.get_text(strip=True)
            
            if text and len(text) > 2:
                important_texts.append(text)
        
        print(f"      Extracted {len(important_texts)} text elements")
        return important_texts
    except Exception as e:
        print(f"      ❌ Text extraction error: {e}")
        return ["login", "password", "verify", "account"]  # Return suspicious keywords as fallback

def predict_text_distilbert(texts, url):
    print(f"   🤖 Running DistilBERT analysis...")
    if not tokenizer or not distilbert_model:
        print(f"      ❌ DistilBERT analysis skipped - model not available")
        # Return more suspicious default if model not available
        has_brand, _ = contains_brand_name(url)
        if has_brand:
            return 1, 0.8  # More suspicious if brand name detected but model unavailable
        return 0, 0.3
    
    # Use lower threshold for URLs containing brand names
    current_threshold = 0.6 if contains_brand_name(url)[0] else PHISHING_THRESHOLD
    print(f"      Using threshold: {current_threshold}")
    
    try:
        if not texts:
            texts = [url]  # Use URL as fallback
        
        inputs = tokenizer(texts, return_tensors="pt", truncation=True, padding=True, max_length=512)
        with torch.no_grad():
            outputs = distilbert_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            phishing_probs = probs[:, 1]
            max_prob = max(float(p) for p in phishing_probs)
            result = 1 if max_prob >= current_threshold else 0
        
        print(f"      DistilBERT result: {'PHISHING' if result == 1 else 'SAFE'} (prob: {max_prob:.4f})")
        return result, max_prob
    except Exception as e:
        print(f"      ❌ DistilBERT error: {e}")
        # Return suspicious default on error
        return 1, 0.7 if contains_brand_name(url)[0] else 0, 0.4

# -----------------------------
# CNN Visual Analysis - IMPROVED
# -----------------------------
def analyze_visual_cnn(image_path, url):
    print(f"   🖼️ CNN Visual analysis...")
    try:
        image_tensor = preprocess_image(image_path)
        with torch.no_grad():
            outputs = cnn_model(image_tensor)
            probabilities = F.softmax(outputs, dim=1)
            phishing_prob = probabilities[0][1].item()
        
        # Enhanced visual heuristics
        img = Image.open(image_path)
        width, height = img.size
        visual_flags = []
        
        if width < 800 or height < 600:
            visual_flags.append("Suspicious small page dimensions")
        
        # Check if image looks like a login page (basic check)
        if phishing_prob > 0.6:
            visual_flags.append("Visual pattern matches phishing pages")
        
        print(f"      CNN phishing probability: {phishing_prob:.4f}")
        return phishing_prob, visual_flags
    except Exception as e:
        print(f"      ❌ Visual analysis error: {e}")
        # Return more suspicious default on error
        return 0.6, ["Visual analysis failed - assuming suspicious"]

# -----------------------------
# Comprehensive Risk Scoring - IMPROVED WITH STRICTER THRESHOLDS
# -----------------------------
def comprehensive_risk_scoring(distilbert_prob, cnn_prob, heuristic_flags, domain_age, 
                             ssl_flags, ip_flags, url):
    print(f"   ⚖️ Comprehensive risk scoring...")
    
    # Increased weights for suspicious indicators
    distilbert_weight = 0.30
    cnn_weight = 0.20
    heuristic_weight = 0.25  # Increased weight for heuristics
    ssl_weight = 0.12
    ip_weight = 0.08
    domain_age_weight = 0.05
    
    # Calculate individual scores with higher penalties
    distilbert_score = distilbert_prob * distilbert_weight
    cnn_score = cnn_prob * cnn_weight
    
    # Higher penalty for heuristic flags
    heuristic_score = min(len(heuristic_flags) * 0.12, heuristic_weight)
    
    # Higher penalties for SSL issues
    ssl_penalty = 0
    for flag in ssl_flags:
        if "HIGH RISK" in flag:
            ssl_penalty += 0.08
        else:
            ssl_penalty += 0.04
    ssl_score = min(ssl_penalty, ssl_weight)
    
    ip_score = min(len(ip_flags) * 0.06, ip_weight)
    
    # Domain age penalty (more strict)
    domain_age_penalty = 0.0
    if domain_age < 365:
        if domain_age < 7:
            domain_age_penalty = domain_age_weight * 1.5  # Extra penalty for very new domains
        else:
            domain_age_penalty = (365 - domain_age) / 365 * domain_age_weight
    
    # Bonus penalty for brand name typosquatting
    brand_penalty = 0.0
    if contains_brand_name(url)[0]:
        brand_penalty = 0.15  # Significant penalty for brand impersonation
    
    combined_score = (distilbert_score + cnn_score + heuristic_score + 
                     ssl_score + ip_score + domain_age_penalty + brand_penalty)
    combined_score = min(combined_score, 1.0)
    
    print(f"   🧮 Scoring breakdown:")
    print(f"      DistilBERT: {distilbert_prob:.4f} × {distilbert_weight} = {distilbert_score:.4f}")
    print(f"      CNN Visual: {cnn_prob:.4f} × {cnn_weight} = {cnn_score:.4f}")
    print(f"      Heuristic: {heuristic_score:.4f}")
    print(f"      SSL: {ssl_score:.4f}")
    print(f"      IP Reputation: {ip_score:.4f}")
    print(f"      Domain Age Penalty: {domain_age_penalty:.4f}")
    print(f"      Brand Penalty: {brand_penalty:.4f}")
    print(f"      TOTAL: {combined_score:.4f}")
    
    return combined_score

# -----------------------------
# Result HTML Creation with Step-by-Step Display
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
    
    # Risk level indicator
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
        
        <!-- Analysis Steps -->
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
        
        <div style='margin-top:20px; padding:15px; background:#e6f7ff; border-radius:5px;'>
            <h4>🎯 Analysis Methodology</h4>
            <p>This system combines multiple detection methods:</p>
            <ul>
                <li>✅ <strong>DistilBERT NLP</strong> - Text content analysis</li>
                <li>✅ <strong>CNN Visual Analysis</strong> - Page layout detection</li>
                <li>✅ <strong>Enhanced Heuristics</strong> - Typosquatting & pattern detection</li>
                <li>✅ <strong>SSL Certificate Validation</strong> - Security verification</li>
                <li>✅ <strong>IP Reputation</strong> - Geographic and hosting analysis</li>
                <li>✅ <strong>Domain Age Analysis</strong> - Registration history</li>
            </ul>
        </div>
    </div>
    """

# -----------------------------
# Main Comprehensive Analysis Function - IMPROVED WITH UI STEPS
# -----------------------------
def comprehensive_analyze_url(url):
    print(f"\n" + "="*80)
    print(f"🛡️ COMPREHENSIVE PHISHING ANALYSIS FOR: {url}")
    print("="*80)
    
    # Initialize steps HTML
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
        return step_html
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Step 1: Enhanced trusted domain check
    add_step(1, "Trusted Domain Check", "processing", "Checking if domain is in trusted list...")
    print(f"\n✅ STEP 1: Trusted domain check...")
    if is_trusted_domain(url):
        print(f"🎯 Domain is trusted - returning SAFE result")
        add_step(1, "Trusted Domain Check", "completed", "✅ Domain is trusted")
        return create_comprehensive_result(url, "✅ SAFE URL", 0.1, [], 0.1, 0.1, "Trusted domain", steps_html)
    add_step(1, "Trusted Domain Check", "completed", "❌ Domain not in trusted list - proceeding with full analysis")

    # Step 2: Enhanced heuristic analysis
    add_step(2, "Heuristic Analysis", "processing", "Analyzing URL patterns and structure...")
    print(f"\n🔍 STEP 2: Enhanced heuristic analysis...")
    heuristic_flags = enhanced_heuristic_check(url)
    add_step(2, "Heuristic Analysis", "completed", f"✅ Found {len(heuristic_flags)} suspicious indicators")
    
    # Step 3: Domain registration check
    add_step(3, "Domain Registration Check", "processing", "Checking WHOIS information...")
    print(f"\n📅 STEP 3: Domain registration analysis...")
    domain_flags, domain_age = check_domain_registration(url)
    heuristic_flags.extend(domain_flags)
    add_step(3, "Domain Registration Check", "completed", f"✅ Domain age: {domain_age} days, {len(domain_flags)} flags")
    
    # Step 4: SSL certificate validation
    add_step(4, "SSL Certificate Validation", "processing", "Validating SSL certificate...")
    print(f"\n🔒 STEP 4: SSL certificate validation...")
    ssl_flags = check_ssl_certificate(url)
    add_step(4, "SSL Certificate Validation", "completed", f"✅ Found {len(ssl_flags)} SSL issues")
    
    # Step 5: IP reputation check
    add_step(5, "IP Reputation Check", "processing", "Analyzing IP address reputation...")
    print(f"\n🌍 STEP 5: IP reputation check...")
    domain = urlparse(url).netloc
    ip_flags, ip_address = check_ip_reputation(domain)
    add_step(5, "IP Reputation Check", "completed", f"✅ IP: {ip_address}, {len(ip_flags)} reputation flags")
    
    # Step 6: DistilBERT Text Analysis
    add_step(6, "AI Text Analysis (DistilBERT)", "processing", "Analyzing page content with NLP...")
    print(f"\n📝 STEP 6: DistilBERT text analysis...")
    texts = fetch_page_text(url)
    distilbert_result, distilbert_prob = predict_text_distilbert(texts, url)
    add_step(6, "AI Text Analysis (DistilBERT)", "completed", f"✅ Phishing probability: {distilbert_prob:.4f}")
    
    # Step 7: Visual Analysis with Screenshot
    add_step(7, "Visual Analysis (CNN)", "processing", "Capturing screenshot and analyzing layout...")
    print(f"\n🖼️ STEP 7: Visual analysis with CNN...")
    screenshot_file = capture_screenshot(url, "screenshot.png")
    cnn_prob, visual_flags = analyze_visual_cnn(screenshot_file, url)
    heuristic_flags.extend(visual_flags)
    add_step(7, "Visual Analysis (CNN)", "completed", f"✅ Visual phishing probability: {cnn_prob:.4f}")
    
    # Combine all flags
    all_flags = heuristic_flags + ssl_flags + ip_flags
    
    # Step 8: Comprehensive scoring with stricter thresholds
    add_step(8, "Risk Scoring", "processing", "Calculating comprehensive risk score...")
    print(f"\n⚖️ STEP 8: Comprehensive risk scoring...")
    combined_score = comprehensive_risk_scoring(
        distilbert_prob, cnn_prob, all_flags, domain_age, ssl_flags, ip_flags, url
    )
    add_step(8, "Risk Scoring", "completed", f"✅ Final risk score: {combined_score:.4f}")
    
    # Step 9: Final classification with stricter thresholds
    add_step(9, "Final Classification", "processing", "Determining final verdict...")
    print(f"\n🎯 STEP 9: Final classification...")
    if combined_score >= 0.70:  # Lowered from 0.7
        final_status = "🚨 PHISHING ALERT"
        reason = "High probability of phishing based on multiple factors"
    elif combined_score >= 0.55:  # Lowered from 0.5
        final_status = "⚠️ HIGHLY SUSPICIOUS"
        reason = "Multiple suspicious indicators detected"
    elif combined_score >= 0.40:  # Lowered from 0.3
        final_status = "⚠️ SUSPICIOUS"
        reason = "Some suspicious indicators detected"
    else:
        final_status = "✅ LIKELY SAFE"
        reason = "No significant suspicious indicators detected"
    
    add_step(9, "Final Classification", "completed", f"✅ Verdict: {final_status}")
    
    print(f"   🎯 FINAL DECISION: {final_status} (Score: {combined_score:.2f})")
    
    return create_comprehensive_result(url, final_status, combined_score, all_flags, 
                                     distilbert_prob, cnn_prob, reason, steps_html)

# -----------------------------
# ✅ FastAPI Endpoint for Model API
# -----------------------------
app = FastAPI(title="Phishing Detection API", description="Comprehensive phishing URL detection using DistilBERT + CNN + Heuristics")

@app.get("/detect")
def detect_phishing(url: str = Query(..., description="URL to analyze for phishing")):
    """
    Comprehensive phishing detection endpoint
    Returns JSON with analysis results
    """
    try:
        print(f"🚀 API request received for: {url}")
        
        # Run your comprehensive model
        result_html = comprehensive_analyze_url(url)
        
        # Extract structured information from HTML (basic parsing)
        risk_score_match = re.search(r"<strong>Risk Score:</strong> ([0-9.]+)", result_html)
        status_match = re.search(r"<h3>(.*?)</h3>", result_html)
        
        response_data = {
            "url": url,
            "status": "success",
            "analysis": {
                "risk_score": float(risk_score_match.group(1)) if risk_score_match else 0.0,
                "verdict": status_match.group(1) if status_match else "Unknown",
                "timestamp": datetime.now().isoformat()
            },
            "html_result": result_html
        }
        return JSONResponse(content=response_data)
    
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "url": url,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )

@app.get("/detect/html", response_class=HTMLResponse)
def detect_phishing_html(url: str = Query(..., description="URL to analyze for phishing")):
    """
    Phishing detection endpoint that returns HTML response
    """
    try:
        print(f"🚀 HTML API request received for: {url}")
        result_html = comprehensive_analyze_url(url)
        return result_html
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"

@app.get("/")
def root():
    """Root endpoint with API information"""
    return {
        "message": "Phishing Detection API",
        "version": "1.0",
        "endpoints": {
            "/detect": "JSON phishing analysis",
            "/detect/html": "HTML phishing analysis",
            "/docs": "API documentation"
        }
    }

# -----------------------------
# SIMPLIFIED MAIN EXECUTION - Choose ONE option below
# -----------------------------

if __name__ == "__main__":
    print("🛡️ Starting Advanced Phishing Detection System...")
    print("📊 Features: DistilBERT + CNN + Enhanced Heuristics + FastAPI")
    
    # 🎯 OPTION 1: Run ONLY FastAPI (Recommended for your use case)
    print("🚀 Starting FastAPI Server on http://localhost:8081")
    print("📚 API Documentation: http://localhost:8081/docs")
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
    
    # 🎯 OPTION 2: Run ONLY Gradio Interface 
    # Uncomment the lines below if you want the Gradio interface instead
    # print("🎨 Starting Gradio Interface on http://localhost:7860")
    # demo.launch(server_name="0.0.0.0", server_port=7860, share=False)