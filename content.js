const phishingKeywords = ["login", "secure", "verify", "account", "update", "password", "bank", "paypal"];

const url = window.location.href.toLowerCase();
let isPhishing = phishingKeywords.some(keyword => url.includes(keyword));

if (isPhishing) {
    alert("⚠️ Warning: This URL may be a phishing attempt!");
    console.warn("Phishing URL Detected:", url);
}
