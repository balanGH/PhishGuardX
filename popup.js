

// Send extracted features to backend
async function sendToBackend(url, data) {
  const payload = { url, features: data };
  const res = await fetch(BACKEND_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!res.ok) throw new Error(`Backend returned ${res.status}`);
  return res.json();
}

class PhishGuardX {
  constructor() {
    this.currentTab = null;
    this.initializeElements();
    this.loadCurrentTab();
    this.attachEventListeners();
    this.updateTimestamp();
  }

  initializeElements() {
    this.elements = {
      url: document.getElementById('current-url'),
      copyBtn: document.getElementById('copy-btn'),
      thumbsUp: document.getElementById('thumbs-up'),
      thumbsDown: document.getElementById('thumbs-down'),
      screenshotBtn: document.getElementById('screenshot-btn'),
      timestamp: document.getElementById('timestamp')
    };
  }

  async loadCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) throw new Error('No active tab found');
      this.currentTab = tabs[0];
      this.displayUrl(this.currentTab.url);
    } catch (error) {
      console.error('Failed to load current tab:', error.message);
      this.elements.url.textContent = 'Error loading URL';
      this.displayUrl(this.currentTab.url);
      this.logPageContent(); // <-- Add this line

    }
  }

  displayUrl(url) {
    try {
      const urlObj = new URL(url);
      this.elements.url.textContent = urlObj.hostname + urlObj.pathname;
      this.elements.url.title = url; // full URL tooltip
    } catch (error) {
      this.elements.url.textContent = url;
    }
  }

  attachEventListeners() {
    // Copy URL
    this.elements.copyBtn.addEventListener('click', () => this.copyUrl());

    // Thumbs up → UI alert only
    this.elements.thumbsUp.addEventListener('click', () => {
      alert('You marked this site as Legitimate ✅');
    });

    // Thumbs down → UI alert only
    this.elements.thumbsDown.addEventListener('click', () => {
      alert('You marked this site as Phishing ⚠️');
    });

    // Screenshot button
    this.elements.screenshotBtn.addEventListener('click', () => this.takeScreenshot());
  }

  async copyUrl() {
    try {
      await navigator.clipboard.writeText(this.currentTab.url);
      alert('URL copied to clipboard! 📋');
    } catch (error) {
      console.error('Failed to copy URL:', error.message);
      alert('Failed to copy URL ❌');
    }
  }

  async takeScreenshot() {
    if (!this.currentTab) return alert("No active tab to capture!");

    if (confirm("Do you want to take a screenshot of this page?")) {
      try {
        // Capture visible tab as DataURL
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: "png" });

        // Convert DataURL to Blob
        const res = await fetch(dataUrl);
        const blob = await res.blob();

        // Attempt to copy to clipboard
        try {
          const item = new ClipboardItem({ "image/png": blob });
          await navigator.clipboard.write([item]);
          console.log("Screenshot copied to clipboard ✅");
        } catch (err) {
          console.warn("Clipboard copy failed:", err);
        }

        // Automatically download screenshot
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "screenshot.png";
        a.click();
        URL.revokeObjectURL(url);

        alert("📸 Screenshot saved as screenshot.png (and copied to clipboard if supported)");
      } catch (error) {
        console.error("Failed to take screenshot:", error);
        alert("❌ Failed to capture screenshot");
      }
    } else {
      alert("Screenshot cancelled ❌");
    }
  }
  async logPageContent() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(tab.id, { action: "getPageContent" }, (response) => {
      if (response?.content) {
        console.log("✅ Current page content:", response.content);
      } else {
        console.warn("No page content received");
      }
    });
  } catch (error) {
    console.error("Failed to get page content:", error);
  }
}


  updateTimestamp() {
    const now = new Date();
    this.elements.timestamp.textContent = now.toLocaleTimeString();
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new PhishGuardX();
});
