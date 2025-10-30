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
      showDetailsBtn: document.getElementById('show-details-btn'),
    };

    // 🧩 Risk score box (new)
    this.riskBox = document.createElement("div");
    this.riskBox.id = "risk-box";
    this.riskBox.style.marginTop = "10px";
    this.riskBox.style.padding = "10px";
    this.riskBox.style.borderRadius = "8px";
    this.riskBox.style.background = "#f8f9fa";
    this.riskBox.style.textAlign = "center";
    this.riskBox.style.boxShadow = "0 1px 3px rgba(0,0,0,0.1)";
    this.riskBox.style.display = "none"; // hidden until data fetched
    document.querySelector(".popup-container").appendChild(this.riskBox);

    // 🧩 Analysis container (existing)
    this.analysisContainer = document.createElement("div");
    this.analysisContainer.id = "analysis-container";
    this.analysisContainer.style.padding = "10px";
    this.analysisContainer.style.overflowY = "auto";
    this.analysisContainer.style.maxHeight = "350px";
    this.analysisContainer.style.display = "none";
    document.querySelector(".popup-container").appendChild(this.analysisContainer);
  }

  async loadCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) throw new Error('No active tab found');
      this.currentTab = tabs[0];
      this.displayUrl(this.currentTab.url);
      this.fetchPhishingAnalysis(this.currentTab.url);
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

    if (this.elements.showDetailsBtn) {
      this.elements.showDetailsBtn.addEventListener('click', () => {
        if (this.analysisContainer.style.display === "none") {
          this.analysisContainer.style.display = "block";
          this.elements.showDetailsBtn.textContent = "🔽 Hide Detailed Analysis";
        } else {
          this.analysisContainer.style.display = "none";
          this.elements.showDetailsBtn.textContent = "📊 Show Detailed Analysis";
        }
      });
    }
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

        try {
          const item = new ClipboardItem({ "image/png": blob });
          await navigator.clipboard.write([item]);
          alert("📸 Screenshot copied to clipboard and saved as file.");
        } catch (err) {
          console.warn("⚠️ Could not copy screenshot automatically. It will open in a new tab.");
          const newTab = window.open(dataUrl, "_blank");
          if (newTab) newTab.focus();
        }

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
      this.analysisContainer.innerHTML = `
        <div id="analysis-waiting" style="padding:14px; display:flex; align-items:center; gap:10px; color:#555;">
          <div style="width:18px;height:18px;border-radius:50%;border:3px solid #e0e0e0;border-top-color:#4a4a4a;animation:pgx-spin 1s linear infinite"></div>
          <div>⏳ Fetching data from server...</div>
        </div>
        <style>@keyframes pgx-spin { to { transform: rotate(360deg); } }</style>
      `;

      const targetUrl = new URL(url).hostname;
      const BACKEND_URL = `http://10.11.155.187:8081/detect?url=${encodeURIComponent(targetUrl)}`;
      const response = await fetch(BACKEND_URL);
      if (!response.ok) throw new Error(`Server returned ${response.status}`);

      const data = await response.json();
      console.log("🟢 Full Backend Response:", data);

      // ✅ Extract risk score
      const score = data.analysis?.risk_score ?? NaN;
      if (!isNaN(score)) {
        this.displayRiskScore(score);
      }

      // 🧩 Update status
      this.elements.statusText.textContent =
        (data.analysis && data.analysis.verdict) ||
        data.status ||
        "Unknown status";

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

      // 🧩 Display backend HTML result
      if (data.html_result) {
        this.analysisContainer.innerHTML = data.html_result;
      } else {
        this.analysisContainer.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
      }

    } catch (error) {
      console.error("❌ Error fetching analysis:", error);
      this.analysisContainer.innerHTML = `<p style='color:red;'>❌ Failed to load analysis: ${error.message}</p>`;
      this.elements.statusText.textContent = "Error";
      this.riskBox.style.display = "none";
    }
  }

  displayRiskScore(score) {
    let color, label;

    if (score < 0.3) {
      color = "green";
      label = "Low Risk";
    } else if (score < 0.6) {
      color = "orange";
      label = "Medium Risk";
    } else {
      color = "red";
      label = "High Risk";
    }

    this.riskBox.style.display = "block";
    this.riskBox.innerHTML = `
      <h3 style="color:${color}; margin:0;">🔒 Risk Score: ${score.toFixed(2)}</h3>
      <p style="margin:4px 0; color:${color}; font-size:13px;">${label}</p>
    `;
  }

  updateTimestamp() {
    const now = new Date();
    this.elements.timestamp.textContent = now.toLocaleTimeString();
  }
}

// ✅ Initialize
document.addEventListener('DOMContentLoaded', () => {
  new PhishGuardX();
});
