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
      timestamp: document.getElementById('timestamp'),
      statusBox: document.getElementById('status-box'),
      statusText: document.getElementById('status-text'),
    };

    // 🆕 Create a result container dynamically
    this.analysisContainer = document.createElement("div");
    this.analysisContainer.id = "analysis-container";
    this.analysisContainer.style.padding = "10px";
    this.analysisContainer.style.overflowY = "auto";
    this.analysisContainer.style.maxHeight = "350px";
    document.querySelector(".popup-container").appendChild(this.analysisContainer);
  }

  async loadCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) throw new Error('No active tab found');
      this.currentTab = tabs[0];
      this.displayUrl(this.currentTab.url);
      this.fetchPhishingAnalysis(this.currentTab.url); // ✅ Fetch and display analysis
    } catch (error) {
      console.error('Failed to load current tab:', error.message);
      this.elements.url.textContent = 'Error loading URL';
    }
  }

  displayUrl(url) {
    try {
      const urlObj = new URL(url);
      this.elements.url.textContent = urlObj.hostname + urlObj.pathname;
      this.elements.url.title = url;
    } catch (error) {
      this.elements.url.textContent = url;
    }
  }

  attachEventListeners() {
    this.elements.copyBtn.addEventListener('click', () => this.copyUrl());
    this.elements.thumbsUp.addEventListener('click', () => alert('✅ You marked this site as Legitimate.'));
    this.elements.thumbsDown.addEventListener('click', () => alert('⚠️ You marked this site as Phishing.'));
    this.elements.screenshotBtn.addEventListener('click', () => this.takeScreenshot());
  }

  async copyUrl() {
    try {
      await navigator.clipboard.writeText(this.currentTab.url);
      alert('✅ URL copied to clipboard!');
    } catch (error) {
      console.error('Failed to copy URL:', error.message);
    }
  }

  async takeScreenshot() {
    if (!this.currentTab) return alert("No active tab to capture!");
    if (confirm("Do you want to take a screenshot of this page?")) {
      try {
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: "png" });
        const res = await fetch(dataUrl);
        const blob = await res.blob();

        // Try to copy to clipboard
        try {
          const item = new ClipboardItem({ "image/png": blob });
          await navigator.clipboard.write([item]);
          alert("📸 Screenshot copied to clipboard and saved as file.");
        } catch (err) {
          console.warn("⚠️ Could not copy screenshot automatically. It will open in a new tab.");
          const newTab = window.open(dataUrl, "_blank");
          if (newTab) newTab.focus();
        }

        // Also download it
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "screenshot.png";
        a.click();
        URL.revokeObjectURL(url);
      } catch (error) {
        console.error("Failed to take screenshot:", error);
        alert("❌ Failed to capture screenshot");
      }
    } else {
      alert("Screenshot cancelled ❌");
    }
  }

  async fetchPhishingAnalysis(url) {
    try {
      // Show a temporary waiting UI
      this.analysisContainer.innerHTML = `
        <div id="analysis-waiting" style="padding:14px; display:flex; align-items:center; gap:10px; color:#555;">
          <div style="width:18px;height:18px;border-radius:50%;border:3px solid #e0e0e0;border-top-color:#4a4a4a;animation:pgx-spin 1s linear infinite"></div>
          <div>⏳ Fetching data from server...</div>
        </div>
        <style>@keyframes pgx-spin { to { transform: rotate(360deg); } }</style>
      `;

      // Extract hostname for your backend
      const targetUrl = new URL(url).hostname;

      // 🔗 Backend endpoint (use your actual one)
      const BACKEND_URL = `http://10.11.155.187:8081/detect?url=${encodeURIComponent(targetUrl)}`;

      // Fetch real data from backend
      const response = await fetch(BACKEND_URL);
      if (!response.ok) throw new Error(`Server returned ${response.status}`);

      const data = await response.json();
      console.log("🟢 Full Backend Response:", data); // ✅ show in console

      // Update status text
      this.elements.statusText.textContent =
        (data.analysis && data.analysis.verdict) ||
        data.status ||
        "Unknown status";

      // Update the status box appearance
      try {
        const score = data.analysis?.risk_score ?? NaN;
        const statusBox = this.elements.statusBox;
        const statusIcon = statusBox.querySelector('#status-icon');

        statusBox.classList.remove('legitimate', 'phishing', 'error');

        if (!isNaN(score)) {
          if (score >= 0.7) {
            statusBox.classList.add('phishing');
            statusIcon.textContent = '🚨';
          } else if (score >= 0.4) {
            statusBox.classList.add('phishing');
            statusIcon.textContent = '⚠️';
          } else {
            statusBox.classList.add('legitimate');
            statusIcon.textContent = '✅';
          }
        }
      } catch (innerErr) {
        console.warn('⚠️ Could not update status box:', innerErr);
      }

      // ✅ Display backend-provided HTML result
      if (data.html_result) {
        this.analysisContainer.innerHTML = data.html_result;
      } else {
        this.analysisContainer.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
      }

    } catch (error) {
      console.error("❌ Error fetching analysis:", error);
      this.analysisContainer.innerHTML = `<p style='color:red;'>❌ Failed to load analysis: ${error.message}</p>`;
      this.elements.statusText.textContent = "Error";
    }
  }


  updateTimestamp() {
    const now = new Date();
    this.elements.timestamp.textContent = now.toLocaleTimeString();
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  new PhishGuardX();
});
